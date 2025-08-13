/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use std::net::ToSocketAddrs;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
mod info;

#[derive(Parser)]
#[clap(version)]
struct Args {}

async fn credentials<F>(env: F) -> anyhow::Result<Option<vector_store::Credentials>>
where
    F: Fn(&'static str) -> Result<String, std::env::VarError>,
{
    let Ok(username) = env("VECTOR_STORE_SCYLLADB_USERNAME") else {
        return Ok(None);
    };
    let Ok(password_file) = env("VECTOR_STORE_SCYLLADB_PASSWORD_FILE") else {
        bail!(
            "credentials: VECTOR_STORE_SCYLLADB_PASSWORD_FILE env required when VECTOR_STORE_SCYLLADB_USERNAME is set"
        );
    };
    let password = tokio::fs::read_to_string(&password_file)
        .await
        .map_err(|e| anyhow!("credentials: failed to read password file: {}", e))?;

    Ok(Some(vector_store::Credentials {
        username,
        password: password.trim().to_string(),
    }))
}

// Index creating/querying is CPU bound task, so that vector-store uses rayon ThreadPool for them.
// From the start there was no need (network traffic seems to be not so high) to support more than
// one thread per network IO bound tasks.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?)
        .with(fmt::layer().with_target(false))
        .init();

    _ = Args::parse();

    tracing::info!(
        "Starting {} version {}",
        info::Info::name(),
        info::Info::version()
    );

    let vector_store_addr = dotenvy::var("VECTOR_STORE_URI")
        .unwrap_or("127.0.0.1:6080".to_string())
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("Unable to parse VECTOR_STORE_URI env (host:port)"))?
        .into();

    let scylladb_uri = dotenvy::var("VECTOR_STORE_SCYLLADB_URI")
        .unwrap_or("127.0.0.1:9042".to_string())
        .into();

    let background_threads = dotenvy::var("VECTOR_STORE_THREADS")
        .ok()
        .and_then(|v| v.parse().ok());

    let node_state = vector_store::new_node_state().await;

    let opensearch_addr = dotenvy::var("VECTOR_STORE_OPENSEARCH_URI").ok();

    let index_factory = if let Some(addr) = opensearch_addr {
        tracing::info!("Using OpenSearch index factory at {addr}");
        vector_store::new_index_factory_opensearch(addr)?
    } else {
        tracing::info!("Using Usearch index factory");
        vector_store::new_index_factory_usearch()?
    };

    let db_actor = vector_store::new_db(
        scylladb_uri,
        node_state.clone(),
        credentials(std::env::var).await?,
    )
    .await?;

    let (_server_actor, addr) = vector_store::run(
        vector_store_addr,
        background_threads,
        node_state,
        db_actor,
        index_factory,
    )
    .await?;
    tracing::info!("listening on {addr}");

    vector_store::wait_for_shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn mock_env(
        vars: HashMap<&'static str, String>,
    ) -> impl Fn(&'static str) -> Result<String, std::env::VarError> {
        move |key| vars.get(key).cloned().ok_or(std::env::VarError::NotPresent)
    }

    #[tokio::test]
    async fn credentials_none_when_no_username() {
        let env = mock_env(HashMap::new());

        let creds = credentials(env).await.unwrap();

        assert!(creds.is_none());
    }

    #[tokio::test]
    async fn credentials_error_when_no_password_file_env() {
        let env = mock_env(HashMap::from([(
            "VECTOR_STORE_SCYLLADB_USERNAME",
            "user".into(),
        )]));

        let result = credentials(env).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "credentials: VECTOR_STORE_SCYLLADB_PASSWORD_FILE env required when VECTOR_STORE_SCYLLADB_USERNAME is set"
        );
    }

    #[tokio::test]
    async fn credentials_error_when_password_file_not_found() {
        let env = mock_env(HashMap::from([
            ("VECTOR_STORE_SCYLLADB_USERNAME", "user".into()),
            (
                "VECTOR_STORE_SCYLLADB_PASSWORD_FILE",
                "/no/such/file/exists".into(),
            ),
        ]));

        let result = credentials(env).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn credentials_success() {
        let mut password_file = NamedTempFile::new().unwrap();
        writeln!(password_file, "my_secret_pass").unwrap();
        let env = mock_env(HashMap::from([
            ("VECTOR_STORE_SCYLLADB_USERNAME", "test_user".into()),
            (
                "VECTOR_STORE_SCYLLADB_PASSWORD_FILE",
                password_file.path().to_str().unwrap().into(),
            ),
        ]));

        let creds = credentials(env).await.unwrap().unwrap();

        assert_eq!(creds.username, "test_user");
        assert_eq!(creds.password, "my_secret_pass");
    }

    #[tokio::test]
    async fn credentials_success_with_trimmed_password() {
        let mut password_file = NamedTempFile::new().unwrap();
        writeln!(password_file, "  \n my_trimmed_pass \t\n").unwrap();
        let env = mock_env(HashMap::from([
            ("VECTOR_STORE_SCYLLADB_USERNAME", "trim_user".into()),
            (
                "VECTOR_STORE_SCYLLADB_PASSWORD_FILE",
                password_file.path().to_str().unwrap().into(),
            ),
        ]));

        let creds = credentials(env).await.unwrap().unwrap();

        assert_eq!(creds.username, "trim_user");
        assert_eq!(creds.password, "my_trimmed_pass");
    }
}
