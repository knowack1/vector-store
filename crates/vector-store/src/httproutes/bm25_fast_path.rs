/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

//! Serves `POST /api/v1/indexes/{keyspace}/{index}/bm25` ahead of the axum router.
//!
//! The bm25 route is the hot path, and its handler is cheap enough that the router's
//! own per-request work (path matching, the matched-path and URL-parameter extensions,
//! the boxed route service, the trace layer) is a large share of its cost. Every other
//! request goes to the router unchanged.

use super::RoutesInnerState;
use super::bm25;
use axum::BoxError;
use axum::Extension;
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::body::Bytes;
use axum::body::HttpBody;
use axum::extract::FromRequest;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::http::Method;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::future::RouteFuture;
use axum_server_dual_protocol::Protocol;
use futures::future::BoxFuture;
use futures::future::Either;
use std::convert::Infallible;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;
use tower_service::Service;

/// The router, with the bm25 route answered before it.
#[derive(Clone)]
pub(crate) struct HttpService {
    router: Router,
    state: RoutesInnerState,
}

impl HttpService {
    pub(super) fn new(router: Router, state: RoutesInnerState) -> Self {
        Self { router, state }
    }

    pub(crate) fn router(&self) -> &Router {
        &self.router
    }
}

impl<B> Service<axum::http::Request<B>> for HttpService
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Either<BoxFuture<'static, Result<Response, Infallible>>, RouteFuture<Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: axum::http::Request<B>) -> Self::Future {
        let request = request.map(Body::new);
        match Bm25Target::of(&request) {
            Some(target) => Either::Left(Box::pin(serve_bm25(self.state.clone(), target, request))),
            None => Either::Right(self.router.call(request)),
        }
    }
}

/// The keyspace and index of a request the bm25 route would match.
struct Bm25Target {
    keyspace: crate::KeyspaceName,
    index_name: crate::IndexName,
}

impl Bm25Target {
    /// Matches only what the router's `Path` extractor would pass through unchanged:
    /// a segment with a `%` escape is left to the router, which decodes it.
    fn of(request: &Request) -> Option<Self> {
        if request.method() != Method::POST {
            return None;
        }
        let (keyspace, index_name) = request
            .uri()
            .path()
            .strip_prefix("/api/v1/indexes/")?
            .strip_suffix("/bm25")?
            .split_once('/')?;
        (is_plain_segment(keyspace) && is_plain_segment(index_name)).then(|| Self {
            keyspace: keyspace.into(),
            index_name: index_name.into(),
        })
    }
}

fn is_plain_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains(['/', '%'])
}

async fn serve_bm25(
    state: RoutesInnerState,
    target: Bm25Target,
    request: Request,
) -> Result<Response, Infallible> {
    let start = Instant::now();
    let protocol = request.extensions().get::<Protocol>().copied();
    let response = match bm25_request(request).await {
        Ok(body) => {
            bm25(
                state,
                protocol.map(Extension),
                target.keyspace,
                target.index_name,
                body,
            )
            .await
        }
        Err(rejection) => rejection,
    };
    log_server_error(&response, start);
    Ok(response)
}

/// Extracts the body as `Json<PostIndexBm25Request>` does, skipping its media-type
/// parse when the header is exactly `application/json`.
async fn bm25_request(request: Request) -> Result<httpapi::PostIndexBm25Request, Response> {
    if !is_exactly_json(request.headers()) {
        return Json::from_request(request, &())
            .await
            .map(|Json(body)| body)
            .map_err(IntoResponse::into_response);
    }
    let bytes = Bytes::from_request(request, &())
        .await
        .map_err(IntoResponse::into_response)?;
    Json::from_bytes(&bytes)
        .map(|Json(body)| body)
        .map_err(IntoResponse::into_response)
}

fn is_exactly_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes() == b"application/json")
}

/// The line the router's `TraceLayer` logs for a server error, which this route bypasses.
fn log_server_error(response: &Response, start: Instant) {
    let status = response.status();
    if status.is_server_error() {
        tracing::error!(
            classification = %format_args!("Status code: {status}"),
            latency = %format_args!("{} ms", start.elapsed().as_millis()),
            "response failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexes::Indexes;
    use crate::metrics::Metrics;
    use axum::http::StatusCode;
    use std::sync::Arc;
    use std::sync::RwLock;
    use tokio::sync::mpsc;

    const BM25_PATH: &str = "/api/v1/indexes/ks/idx/bm25";

    async fn service(use_tls: bool) -> HttpService {
        let (engine, _) = mpsc::channel(1);
        let (node_state, _) = mpsc::channel(1);
        let (internals, _) = mpsc::channel(1);
        super::super::new(
            Arc::new(RwLock::new(Indexes::new())),
            engine,
            Arc::new(Metrics::new()),
            node_state,
            internals,
            "test".to_string(),
            use_tls,
        )
        .await
    }

    fn post(path: &str, content_type: Option<&str>, body: &'static str) -> Request {
        let builder = axum::http::Request::post(path);
        let builder = match content_type {
            Some(content_type) => builder.header(header::CONTENT_TYPE, content_type),
            None => builder,
        };
        builder.body(Body::from(body)).unwrap()
    }

    async fn parts(response: Response) -> (StatusCode, Option<String>, Bytes) {
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_string());
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, content_type, body)
    }

    async fn through_both(
        service: &HttpService,
        request: impl Fn() -> Request,
    ) -> [(StatusCode, Option<String>, Bytes); 2] {
        let fast = service.clone().call(request()).await.unwrap();
        let routed = service.router().clone().call(request()).await.unwrap();
        [parts(fast).await, parts(routed).await]
    }

    fn target(method: Method, path: &str) -> Option<(String, String)> {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        Bm25Target::of(&request).map(|target| {
            (
                target.keyspace.as_ref().to_string(),
                target.index_name.as_ref().to_string(),
            )
        })
    }

    #[test]
    fn bm25_target_matches_a_post_to_the_bm25_route() {
        assert_eq!(
            target(Method::POST, "/api/v1/indexes/ks/idx/bm25?x=1"),
            Some(("ks".to_string(), "idx".to_string()))
        );
    }

    #[test]
    fn bm25_target_leaves_every_other_request_to_the_router() {
        for (method, path) in [
            (Method::GET, BM25_PATH),
            (Method::POST, "/api/v1/indexes/ks/idx/bm25/"),
            (Method::POST, "/api/v1/indexes/ks/idx/extra/bm25"),
            (Method::POST, "/api/v1/indexes//idx/bm25"),
            (Method::POST, "/api/v1/indexes/ks//bm25"),
            (Method::POST, "/api/v1/indexes/k%73/idx/bm25"),
            (Method::POST, "/api/v1/indexes/ks/idx/ann"),
            (Method::POST, "/api/v1/indexes/ks/idx/highlight"),
            (Method::POST, "/api/v1/indexes/bm25"),
        ] {
            assert_eq!(target(method.clone(), path), None, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn bm25_fast_path_answers_as_the_router_does() {
        let service = service(false).await;
        for (content_type, body) in [
            (Some("application/json"), r#"{"query":"fox","limit":5}"#),
            (
                Some("application/json; charset=utf-8"),
                r#"{"query":"fox"}"#,
            ),
            (Some("application/json"), r#"{"query":"#),
            (Some("application/json"), r#"{"limit":5}"#),
            (Some("application/json"), r#"{"query":"fox","limit":0}"#),
            (Some("text/plain"), r#"{"query":"fox"}"#),
            (None, r#"{"query":"fox"}"#),
        ] {
            let [fast, routed] =
                through_both(&service, || post(BM25_PATH, content_type, body)).await;
            assert_eq!(fast, routed, "{content_type:?} {body}");
        }
    }

    #[tokio::test]
    async fn bm25_fast_path_rejects_plain_http_as_the_router_does_when_tls_is_on() {
        let service = service(true).await;
        let request = || {
            let mut request = post(BM25_PATH, Some("application/json"), r#"{"query":"fox"}"#);
            request.extensions_mut().insert(Protocol::Plain);
            request
        };

        let [fast, routed] = through_both(&service, request).await;

        assert_eq!(fast.0, StatusCode::FORBIDDEN);
        assert_eq!(fast, routed);
    }

    #[tokio::test]
    async fn bm25_fast_path_passes_other_routes_to_the_router() {
        let service = service(false).await;
        let request = || {
            axum::http::Request::get("/api/v1/indexes")
                .body(Body::empty())
                .unwrap()
        };

        let [fast, routed] = through_both(&service, request).await;

        assert_eq!(fast.0, StatusCode::OK);
        assert_eq!(fast, routed);
    }
}
