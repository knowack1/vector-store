/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use crate::db_basic;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use reqwest::StatusCode;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::watch;
use vector_store::Config;
use vector_store::httproutes::PostIndexAnnRequest;

fn create_temp_file<C: AsRef<[u8]>>(content: C) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_ref()).unwrap();
    file
}

async fn run_server(
    addr: core::net::SocketAddr,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    mtls_ca_cert_path: Option<PathBuf>,
) -> (impl Sized, core::net::SocketAddr, impl Sized) {
    let node_state = vector_store::new_node_state().await;
    let internals = vector_store::new_internals();
    let (db_actor, _db) = db_basic::new(node_state.clone());
    let (_, rx) = watch::channel(Arc::new(Config::default()));
    let index_factory = vector_store::new_index_factory_usearch(rx).unwrap();

    let config = vector_store::Config {
        vector_store_addr: addr,
        tls_cert_path,
        tls_key_path,
        mtls_ca_cert_path,
        ..Default::default()
    };

    let (_config_tx, config_rx) = watch::channel(Arc::new(config));

    let (server, addr) =
        vector_store::run(node_state, db_actor, internals, index_factory, config_rx)
            .await
            .unwrap();

    (server, addr, _config_tx)
}

#[tokio::test]
async fn test_https_server_responds() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    crate::enable_tracing();

    let addr = core::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let generated = rcgen::generate_simple_self_signed(vec![addr.ip().to_string()]).unwrap();

    let cert_file = create_temp_file(generated.cert.pem().as_bytes());
    let key_file = create_temp_file(generated.signing_key.serialize_pem().as_bytes());

    let (_server, addr, _config_tx) = run_server(
        addr,
        Some(cert_file.path().to_path_buf()),
        Some(key_file.path().to_path_buf()),
        None,
    )
    .await;

    let client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(generated.cert.pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let response = client
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "Request to HTTP server metrics failed with status: {}",
        response.status()
    );

    let response = client
        .get(format!("https://{addr}/api/v1/status"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "Request to HTTPS server failed with status: {}",
        response.status()
    );

    let response = client
        .get(format!("http://{addr}/api/v1/status"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "Request to HTTP server failed with status: {}",
        response.status()
    );

    let response = client
        .post(format!("http://{addr}/api/v1/indexes/table/index/ann"))
        .json(&PostIndexAnnRequest {
            vector: vec![1.0].into(),
            filter: None,
            limit: NonZeroUsize::new(1).unwrap().into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = client
        .post(format!("https://{addr}/api/v1/indexes/table/index/ann"))
        .json(&PostIndexAnnRequest {
            vector: vec![1.0].into(),
            filter: None,
            limit: NonZeroUsize::new(1).unwrap().into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

struct CaBundle {
    cert_pem: String,
    params: CertificateParams,
    key_pair: KeyPair,
}

struct SignedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca() -> CaBundle {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    CaBundle {
        cert_pem: cert.pem(),
        params,
        key_pair,
    }
}

fn generate_signed_cert(ca: &CaBundle, subject_alt_names: Vec<String>) -> SignedCert {
    let mut params = CertificateParams::new(subject_alt_names).unwrap();
    params.is_ca = IsCa::NoCa;
    let key_pair = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca.params, &ca.key_pair);
    let cert = params.signed_by(&key_pair, &issuer).unwrap();
    SignedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

#[tokio::test]
async fn test_mtls_accepts_valid_client_cert() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    crate::enable_tracing();

    let addr = core::net::SocketAddr::from(([127, 0, 0, 1], 0));

    let ca = generate_ca();
    let server_cert = generate_signed_cert(&ca, vec![addr.ip().to_string()]);
    let client_cert = generate_signed_cert(&ca, vec!["client".to_string()]);

    let ca_file = create_temp_file(ca.cert_pem.as_bytes());
    let server_cert_file = create_temp_file(server_cert.cert_pem.as_bytes());
    let server_key_file = create_temp_file(server_cert.key_pem.as_bytes());

    let (_server, addr, _config_tx) = run_server(
        addr,
        Some(server_cert_file.path().to_path_buf()),
        Some(server_key_file.path().to_path_buf()),
        Some(ca_file.path().to_path_buf()),
    )
    .await;

    let client_identity_pem = format!("{}{}", client_cert.key_pem, client_cert.cert_pem,);
    let identity = reqwest::Identity::from_pem(client_identity_pem.as_bytes()).unwrap();

    let client_with_cert = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
        .identity(identity)
        .build()
        .unwrap();

    let response = client_with_cert
        .get(format!("https://{addr}/api/v1/status"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "mTLS request with valid client cert should succeed, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_mtls_rejects_missing_client_cert() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    crate::enable_tracing();

    let addr = core::net::SocketAddr::from(([127, 0, 0, 1], 0));

    let ca = generate_ca();
    let server_cert = generate_signed_cert(&ca, vec![addr.ip().to_string()]);

    let ca_file = create_temp_file(ca.cert_pem.as_bytes());
    let server_cert_file = create_temp_file(server_cert.cert_pem.as_bytes());
    let server_key_file = create_temp_file(server_cert.key_pem.as_bytes());

    let (_server, addr, _config_tx) = run_server(
        addr,
        Some(server_cert_file.path().to_path_buf()),
        Some(server_key_file.path().to_path_buf()),
        Some(ca_file.path().to_path_buf()),
    )
    .await;

    let client_without_cert = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let result = client_without_cert
        .get(format!("https://{addr}/api/v1/status"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "mTLS request without client cert should fail at TLS handshake"
    );
}

#[tokio::test]
async fn test_mtls_rejects_untrusted_client_cert() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    crate::enable_tracing();

    let addr = core::net::SocketAddr::from(([127, 0, 0, 1], 0));

    let ca = generate_ca();
    let untrusted_ca = generate_ca();
    let server_cert = generate_signed_cert(&ca, vec![addr.ip().to_string()]);
    let untrusted_client = generate_signed_cert(&untrusted_ca, vec!["rogue".to_string()]);

    let ca_file = create_temp_file(ca.cert_pem.as_bytes());
    let server_cert_file = create_temp_file(server_cert.cert_pem.as_bytes());
    let server_key_file = create_temp_file(server_cert.key_pem.as_bytes());

    let (_server, addr, _config_tx) = run_server(
        addr,
        Some(server_cert_file.path().to_path_buf()),
        Some(server_key_file.path().to_path_buf()),
        Some(ca_file.path().to_path_buf()),
    )
    .await;

    let rogue_identity_pem = format!("{}{}", untrusted_client.key_pem, untrusted_client.cert_pem,);
    let identity = reqwest::Identity::from_pem(rogue_identity_pem.as_bytes()).unwrap();

    let client_with_untrusted_cert = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
        .identity(identity)
        .build()
        .unwrap();

    let result = client_with_untrusted_cert
        .get(format!("https://{addr}/api/v1/status"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "mTLS request with untrusted client cert should fail at TLS handshake"
    );
}
