/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use crate::db_basic;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::CertifiedIssuer;
use rcgen::CertifiedKey;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::SanType;
use reqwest::StatusCode;
use std::io::Write;
use std::net::IpAddr;
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
        ..Default::default()
    };

    let (_config_tx, config_rx) = watch::channel(Arc::new(config));

    let (server, addr, _mtls_addr) =
        vector_store::run(node_state, db_actor, internals, index_factory, config_rx)
            .await
            .unwrap();

    (server, addr, _config_tx)
}

#[tokio::test]
async fn test_https_server_responds() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // may already be installed by another test running in parallel

    crate::enable_tracing();

    let addr = core::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![addr.ip().to_string()]).unwrap();

    let cert_file = create_temp_file(cert.pem().as_bytes());
    let key_file = create_temp_file(signing_key.serialize_pem().as_bytes());

    let (_server, addr, _config_tx) = run_server(
        addr,
        Some(cert_file.path().to_path_buf()),
        Some(key_file.path().to_path_buf()),
    )
    .await;

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
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

fn generate_ca() -> CertifiedIssuer<'static, KeyPair> {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    CertifiedIssuer::self_signed(ca_params, ca_key).unwrap()
}

fn generate_cert_signed_by(
    ca: &CertifiedIssuer<'_, KeyPair>,
    client_auth: bool,
    ip_sans: &[IpAddr],
) -> CertifiedKey<KeyPair> {
    let child_key = KeyPair::generate().unwrap();
    let mut child_params = CertificateParams::default();
    if client_auth {
        child_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    for ip in ip_sans {
        child_params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    let child_cert = child_params.signed_by(&child_key, ca).unwrap();
    CertifiedKey {
        cert: child_cert,
        signing_key: child_key,
    }
}

#[tokio::test]
async fn test_mtls_server_requires_client_cert() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // may already be installed by another test

    crate::enable_tracing();

    let ca = generate_ca();

    let server_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let server = generate_cert_signed_by(&ca, false, &[server_ip]);

    let valid_client = generate_cert_signed_by(&ca, true, &[]);

    let rogue_ca = generate_ca();
    let rogue_client = generate_cert_signed_by(&rogue_ca, true, &[]);

    let server_cert_file = create_temp_file(server.cert.pem().as_bytes());
    let server_key_file = create_temp_file(server.signing_key.serialize_pem().as_bytes());
    let ca_cert_pem = AsRef::<rcgen::Certificate>::as_ref(&ca).pem();
    let ca_cert_file = create_temp_file(ca_cert_pem.as_bytes());

    let node_state = vector_store::new_node_state().await;
    let internals = vector_store::new_internals();
    let (db_actor, _db) = db_basic::new(node_state.clone());
    let (_, rx) = watch::channel(Arc::new(Config::default()));
    let index_factory = vector_store::new_index_factory_usearch(rx).unwrap();

    let config = vector_store::Config {
        vector_store_addr: "127.0.0.1:0".parse().unwrap(),
        tls_cert_path: Some(server_cert_file.path().to_path_buf()),
        tls_key_path: Some(server_key_file.path().to_path_buf()),
        mtls_addr: Some("127.0.0.1:0".parse().unwrap()),
        mtls_ca_cert_path: Some(ca_cert_file.path().to_path_buf()),
        ..Default::default()
    };

    let (_config_tx, config_rx) = watch::channel(Arc::new(config));
    let (_server, _main_addr, mtls_addr) =
        vector_store::run(node_state, db_actor, internals, index_factory, config_rx)
            .await
            .unwrap();
    let mtls_addr = mtls_addr.expect("mTLS server should be listening");

    let server_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap();

    let mut valid_client_pem = valid_client.cert.pem().into_bytes();
    valid_client_pem.extend_from_slice(valid_client.signing_key.serialize_pem().as_bytes());
    let valid_identity = reqwest::Identity::from_pem(&valid_client_pem).unwrap();

    let client_with_cert = reqwest::Client::builder()
        .add_root_certificate(server_ca.clone())
        .identity(valid_identity)
        .build()
        .unwrap();

    let response = client_with_cert
        .get(format!("https://{mtls_addr}/api/v1/status"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "valid client cert should be accepted, got {}",
        response.status()
    );

    let client_no_cert = reqwest::Client::builder()
        .add_root_certificate(server_ca.clone())
        .build()
        .unwrap();

    let result = client_no_cert
        .get(format!("https://{mtls_addr}/api/v1/status"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "request without client cert should fail, got {:?}",
        result.ok().map(|r| r.status())
    );

    let mut rogue_client_pem = rogue_client.cert.pem().into_bytes();
    rogue_client_pem.extend_from_slice(rogue_client.signing_key.serialize_pem().as_bytes());
    let rogue_identity = reqwest::Identity::from_pem(&rogue_client_pem).unwrap();

    let client_rogue_cert = reqwest::Client::builder()
        .add_root_certificate(server_ca.clone())
        .identity(rogue_identity)
        .build()
        .unwrap();

    let result = client_rogue_cert
        .get(format!("https://{mtls_addr}/api/v1/status"))
        .send()
        .await;
    assert!(
        result.is_err(),
        "request with untrusted client cert should fail, got {:?}",
        result.ok().map(|r| r.status())
    );
}
