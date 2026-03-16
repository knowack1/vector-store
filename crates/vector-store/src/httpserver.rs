/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use crate::Config;
use crate::engine::Engine;
use crate::httproutes;
use crate::internals::Internals;
use crate::metrics::Metrics;
use crate::node_state::NodeState;
use axum_server::Handle;
use axum_server::accept::NoDelayAcceptor;
use axum_server::tls_rustls::RustlsConfig;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;
use tokio::time;

pub(crate) enum HttpServer {}

async fn load_tls_config(config: &Config) -> anyhow::Result<Option<RustlsConfig>> {
    match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let config = RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {e}"))?;
            Ok(Some(config))
        }
        _ => Ok(None),
    }
}

async fn load_mtls_root_store(
    ca_cert_path: Option<&std::path::Path>,
    mtls_addr: SocketAddr,
) -> anyhow::Result<RootCertStore> {
    if let Some(ca_cert_path) = ca_cert_path {
        tracing::info!(
            "Loading mTLS config for {mtls_addr} with CA cert from {}",
            ca_cert_path.display()
        );

        let ca_pem = tokio::fs::read(ca_cert_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read mTLS CA certificate: {e}"))?;

        let ca_certs: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(&ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse mTLS CA certificate PEM: {e}"))?;

        let mut root_store = RootCertStore::empty();
        let (added, ignored) = root_store.add_parsable_certificates(ca_certs);
        if added == 0 {
            return Err(anyhow::anyhow!(
                "No valid CA certificates found in {}",
                ca_cert_path.display()
            ));
        }
        if ignored > 0 {
            tracing::warn!(
                "{ignored} CA certificate(s) could not be parsed from {}",
                ca_cert_path.display()
            );
        }
        Ok(root_store)
    } else {
        Err(anyhow::anyhow!(
            "VECTOR_STORE_MTLS_CA_CERT_PATH is not set. \
            An explicit CA certificate bundle is required to enable mTLS client \
            authentication for {mtls_addr}."
        ))
    }
}

async fn load_mtls_config(config: &Config) -> anyhow::Result<Option<RustlsConfig>> {
    let (Some(mtls_addr), Some(cert_path), Some(key_path)) = (
        &config.mtls_addr,
        &config.tls_cert_path,
        &config.tls_key_path,
    ) else {
        return Ok(None);
    };

    let root_store = load_mtls_root_store(config.mtls_ca_cert_path.as_deref(), *mtls_addr).await?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build client certificate verifier: {e}"))?;

    let base_tls = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load mTLS server certificate: {e}"))?;

    let base_server_config = base_tls.get_inner();
    let mut mtls_server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(base_server_config.cert_resolver.clone());
    mtls_server_config.alpn_protocols = base_server_config.alpn_protocols.clone();

    Ok(Some(RustlsConfig::from_config(Arc::new(
        mtls_server_config,
    ))))
}

fn protocol(tls_config: &Option<RustlsConfig>) -> &'static str {
    if tls_config.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    }
}

/// Retry spawning a server with exponential backoff
async fn spawn_server_with_retry(
    config: &Config,
    state: Sender<NodeState>,
    engine: Sender<Engine>,
    metrics: Arc<Metrics>,
    internals: Sender<Internals>,
    index_engine_version: String,
) -> anyhow::Result<(Handle, SocketAddr)> {
    let mut retry_delay = Duration::from_millis(50);
    let max_retries = 10;

    for attempt in 1..=max_retries {
        if attempt > 1 {
            time::sleep(retry_delay).await;
        }

        match spawn_server(
            config,
            state.clone(),
            engine.clone(),
            metrics.clone(),
            internals.clone(),
            index_engine_version.clone(),
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < max_retries {
                    tracing::warn!(
                        "Failed to start HTTP server (attempt {}/{}): {e}, retrying in {:?}",
                        attempt,
                        max_retries,
                        retry_delay
                    );
                    // Exponential backoff: 50ms, 100ms, 200ms, 400ms, 800ms, 1600ms, ...
                    retry_delay =
                        Duration::from_millis((retry_delay.as_millis() * 2).min(2000) as u64);
                } else {
                    return Err(e);
                }
            }
        }
    }

    unreachable!()
}

async fn spawn_mtls_server_with_retry(
    config: &Config,
    state: Sender<NodeState>,
    engine: Sender<Engine>,
    metrics: Arc<Metrics>,
    internals: Sender<Internals>,
    index_engine_version: String,
) -> anyhow::Result<Option<(Handle, SocketAddr)>> {
    let mut retry_delay = Duration::from_millis(50);
    let max_retries = 10;

    for attempt in 1..=max_retries {
        if attempt > 1 {
            time::sleep(retry_delay).await;
        }

        match spawn_mtls_server(
            config,
            state.clone(),
            engine.clone(),
            metrics.clone(),
            internals.clone(),
            index_engine_version.clone(),
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < max_retries {
                    tracing::warn!(
                        "Failed to start mTLS server (attempt {}/{}): {e}, retrying in {:?}",
                        attempt,
                        max_retries,
                        retry_delay
                    );
                    retry_delay =
                        Duration::from_millis((retry_delay.as_millis() * 2).min(2000) as u64);
                } else {
                    return Err(e);
                }
            }
        }
    }

    unreachable!()
}

pub(crate) async fn new(
    state: Sender<NodeState>,
    engine: Sender<Engine>,
    metrics: Arc<Metrics>,
    internals: Sender<Internals>,
    index_engine_version: String,
    mut config_rx: watch::Receiver<Arc<Config>>,
) -> anyhow::Result<(Sender<HttpServer>, SocketAddr, Option<SocketAddr>)> {
    // minimal size as channel is used as a lifetime guard
    const CHANNEL_SIZE: usize = 1;
    let (tx, mut rx) = mpsc::channel(CHANNEL_SIZE);

    let initial_config = config_rx.borrow().clone();

    // Start initial server and get actual bound address
    let (initial_handle, actual_addr) = spawn_server_with_retry(
        &initial_config,
        state.clone(),
        engine.clone(),
        metrics.clone(),
        internals.clone(),
        index_engine_version.clone(),
    )
    .await?;

    let initial_mtls = spawn_mtls_server_with_retry(
        &initial_config,
        state.clone(),
        engine.clone(),
        metrics.clone(),
        internals.clone(),
        index_engine_version.clone(),
    )
    .await?;

    let mtls_actual_addr = initial_mtls.as_ref().map(|(_, addr)| *addr);

    // Spawn supervisor task that monitors config changes and manages server restarts
    tokio::spawn({
        let state = state.clone();
        let engine = engine.clone();
        let metrics = metrics.clone();
        let index_engine_version = index_engine_version.clone();

        async move {
            let mut current_handle = initial_handle;
            let mut current_addr = initial_config.vector_store_addr;
            let mut current_tls_cert = initial_config.tls_cert_path.clone();
            let mut current_tls_key = initial_config.tls_key_path.clone();
            let mut current_mtls_handle: Option<Handle> = initial_mtls.map(|(handle, _)| handle);
            let mut current_mtls_addr = initial_config.mtls_addr;
            let mut current_mtls_ca_cert = initial_config.mtls_ca_cert_path.clone();

            loop {
                tokio::select! {
                    result = rx.recv() => {
                        if result.is_none() {
                            break;
                        }
                    }
                    result = config_rx.changed() => {
                        if result.is_err() {
                            break;
                        }

                        let new_config = config_rx.borrow().clone();

                        // Check if HTTP server config changed
                        let addr_changed = current_addr != new_config.vector_store_addr;
                        let tls_changed = current_tls_cert != new_config.tls_cert_path
                            || current_tls_key != new_config.tls_key_path;

                        if addr_changed || tls_changed {
                            let mut changes = Vec::new();
                            if addr_changed {
                                changes.push(format!("address {} -> {}", current_addr, new_config.vector_store_addr));
                            }
                            if tls_changed {
                                let old_tls = if current_tls_cert.is_some() && current_tls_key.is_some() {
                                    "enabled"
                                } else {
                                    "disabled"
                                };
                                let new_tls = if new_config.tls_cert_path.is_some() && new_config.tls_key_path.is_some() {
                                    "enabled"
                                } else {
                                    "disabled"
                                };
                                changes.push(format!("TLS {} -> {}", old_tls, new_tls));
                            }

                            tracing::info!("HTTP server configuration changed ({}), reloading...", changes.join(", "));

                            // Gracefully shutdown old server and wait for it to complete
                            tracing::info!("Shutting down old HTTP server");
                            current_handle.graceful_shutdown(Some(Duration::from_secs(10)));

                            // Start new server with retry
                            match spawn_server_with_retry(
                                &new_config,
                                state.clone(),
                                engine.clone(),
                                metrics.clone(),
                                internals.clone(),
                                index_engine_version.clone(),
                            )
                            .await
                            {
                                Ok((handle, new_actual_addr)) => {
                                    current_handle = handle;
                                    current_addr = new_config.vector_store_addr;
                                    current_tls_cert = new_config.tls_cert_path.clone();
                                    current_tls_key = new_config.tls_key_path.clone();

                                    let protocol = if new_config.tls_cert_path.is_some() { "HTTPS" } else { "HTTP" };
                                    tracing::info!("{} server reloaded successfully on {}", protocol, new_actual_addr);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to reload HTTP server: {e}");
                                    tracing::error!("HTTP server is now offline - previous server was shut down but new server failed to start");
                                }
                            }
                        }

                        let mtls_addr_changed = current_mtls_addr != new_config.mtls_addr;
                        let mtls_ca_changed = current_mtls_ca_cert != new_config.mtls_ca_cert_path;
                        let mtls_tls_changed = tls_changed;

                        if mtls_addr_changed || mtls_ca_changed || mtls_tls_changed {
                            if let Some(handle) = current_mtls_handle.take() {
                                tracing::info!("Shutting down old mTLS server");
                                handle.graceful_shutdown(Some(Duration::from_secs(10)));
                            }

                            match spawn_mtls_server_with_retry(
                                &new_config,
                                state.clone(),
                                engine.clone(),
                                metrics.clone(),
                                internals.clone(),
                                index_engine_version.clone(),
                            )
                            .await
                            {
                                Ok(Some((handle, addr))) => {
                                    tracing::info!("mTLS server reloaded successfully on {addr}");
                                    current_mtls_handle = Some(handle);
                                }
                                Ok(None) => {
                                    tracing::info!("mTLS server disabled (no mTLS configuration)");
                                    current_mtls_handle = None;
                                }
                                Err(e) => {
                                    tracing::error!("Failed to reload mTLS server: {e}");
                                    current_mtls_handle = None;
                                }
                            }

                            current_mtls_addr = new_config.mtls_addr;
                            current_mtls_ca_cert = new_config.mtls_ca_cert_path.clone();
                        }
                    }
                }
            }

            // Final shutdown
            tracing::info!("HTTP server shutting down");
            current_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            if let Some(handle) = current_mtls_handle {
                tracing::info!("mTLS server shutting down");
                handle.graceful_shutdown(Some(Duration::from_secs(10)));
            }
            // Brief delay to allow clean shutdown
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    Ok((tx, actual_addr, mtls_actual_addr))
}

/// Spawn a new HTTP server instance with the given configuration
/// Returns the handle and the actual bound address
async fn spawn_server(
    config: &Config,
    state: Sender<NodeState>,
    engine: Sender<Engine>,
    metrics: Arc<Metrics>,
    internals: Sender<Internals>,
    index_engine_version: String,
) -> anyhow::Result<(Handle, SocketAddr)> {
    let tls_config = load_tls_config(config).await?;
    let protocol = protocol(&tls_config);
    let addr = config.vector_store_addr;

    let handle = Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            let result = match tls_config {
                Some(tls_config) => {
                    axum_server_dual_protocol::bind_dual_protocol(addr, tls_config)
                        .handle(handle)
                        .serve(
                            httproutes::new(
                                engine,
                                metrics,
                                state,
                                internals,
                                index_engine_version,
                                true,
                            )
                            .into_make_service(),
                        )
                        .await
                }
                _ => {
                    axum_server::bind(addr)
                        .handle(handle)
                        .acceptor(NoDelayAcceptor::new())
                        .serve(
                            httproutes::new(
                                engine,
                                metrics,
                                state,
                                internals,
                                index_engine_version,
                                false,
                            )
                            .into_make_service(),
                        )
                        .await
                }
            };
            result.unwrap_or_else(|e| panic!("failed to run {protocol} server: {e}"));
        }
    });

    // Wait for server to be listening and get actual bound address
    // Add timeout to prevent hanging forever if server fails to start
    let actual_addr = time::timeout(Duration::from_secs(5), handle.listening())
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for server to start"))?
        .ok_or(anyhow::anyhow!(
            "server failed to start - listening notification not received"
        ))?;

    Ok((handle, actual_addr))
}

async fn spawn_mtls_server(
    config: &Config,
    state: Sender<NodeState>,
    engine: Sender<Engine>,
    metrics: Arc<Metrics>,
    internals: Sender<Internals>,
    index_engine_version: String,
) -> anyhow::Result<Option<(Handle, SocketAddr)>> {
    let Some(mtls_tls_config) = load_mtls_config(config).await? else {
        return Ok(None);
    };

    let addr = config
        .mtls_addr
        .expect("mtls_addr must be set when mTLS config is loaded");

    let handle = Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            let result = axum_server::bind_rustls(addr, mtls_tls_config)
                .handle(handle)
                .serve(
                    httproutes::new(
                        engine,
                        metrics,
                        state,
                        internals,
                        index_engine_version,
                        true,
                    )
                    .into_make_service(),
                )
                .await;
            result.unwrap_or_else(|e| panic!("failed to run mTLS server: {e}"));
        }
    });

    // Wait for server to be listening and get actual bound address
    let actual_addr = time::timeout(Duration::from_secs(5), handle.listening())
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for mTLS server to start"))?
        .ok_or(anyhow::anyhow!(
            "mTLS server failed to start - listening notification not received"
        ))?;

    tracing::info!("mTLS server listening on {actual_addr}");

    Ok(Some((handle, actual_addr)))
}
