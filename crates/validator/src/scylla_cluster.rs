/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time;
use tracing::Instrument;
use tracing::debug;
use tracing::debug_span;

pub(crate) enum ScyllaCluster {
    Version {
        tx: oneshot::Sender<String>,
    },
    Start {
        vs_uri: String,
        db_ip: Ipv4Addr,
        conf: Option<Vec<u8>>,
    },
    WaitForReady {
        tx: oneshot::Sender<bool>,
    },
    Stop,
    Up {
        vs_uri: String,
        conf: Option<Vec<u8>>,
    },
    Down,
}

pub(crate) trait ScyllaClusterExt {
    /// Returns the version of the ScyllaDB executable.
    async fn version(&self) -> String;

    /// Starts the ScyllaDB cluster with the given vector store URI and database IP.
    async fn start(&self, vs_uri: String, db_ip: Ipv4Addr, conf: Option<Vec<u8>>);

    /// Stops the ScyllaDB instance.
    async fn stop(&self);

    /// Waits for the ScyllaDB cluster to be ready.
    async fn wait_for_ready(&self) -> bool;

    /// Starts a paused instance back again.
    async fn up(&self, vs_uri: String, conf: Option<Vec<u8>>);

    /// Pauses an instance
    async fn down(&self);
}

impl ScyllaClusterExt for mpsc::Sender<ScyllaCluster> {
    async fn version(&self) -> String {
        let (tx, rx) = oneshot::channel();
        self.send(ScyllaCluster::Version { tx })
            .await
            .expect("ScyllaClusterExt::version: internal actor should receive request");
        rx.await
            .expect("ScyllaClusterExt::version: internal actor should send response")
    }

    async fn start(&self, vs_uri: String, db_ip: Ipv4Addr, conf: Option<Vec<u8>>) {
        self.send(ScyllaCluster::Start {
            vs_uri,
            db_ip,
            conf,
        })
        .await
        .expect("ScyllaClusterExt::start: internal actor should receive request");
    }

    async fn stop(&self) {
        self.send(ScyllaCluster::Stop)
            .await
            .expect("ScyllaClusterExt::stop: internal actor should receive request");
    }

    async fn wait_for_ready(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        self.send(ScyllaCluster::WaitForReady { tx })
            .await
            .expect("ScyllaClusterExt::wait_for_ready: internal actor should receive request");
        rx.await
            .expect("ScyllaClusterExt::wait_for_ready: internal actor should send response")
    }

    async fn up(&self, vs_uri: String, conf: Option<Vec<u8>>) {
        self.send(ScyllaCluster::Up { vs_uri, conf })
            .await
            .expect("ScyllaClusterExt::up: internal actor should receive request")
    }

    async fn down(&self) {
        self.send(ScyllaCluster::Down)
            .await
            .expect("ScyllaClusterExt::down: internal actor should receive request")
    }
}

pub(crate) async fn new(
    path: PathBuf,
    default_conf: PathBuf,
    verbose: bool,
) -> mpsc::Sender<ScyllaCluster> {
    let (tx, mut rx) = mpsc::channel(10);

    assert!(
        crate::executable_exists(&path).await,
        "scylla executable '{path:?}' does not exist"
    );
    assert!(
        crate::file_exists(&default_conf).await,
        "scylla config '{default_conf:?}' does not exist"
    );

    let mut state = State::new(path, default_conf, verbose).await;

    tokio::spawn(
        async move {
            debug!("starting");

            while let Some(msg) = rx.recv().await {
                process(msg, &mut state).await;
            }

            debug!("finished");
        }
        .instrument(debug_span!("db")),
    );

    tx
}

struct State {
    path: PathBuf,
    default_conf: PathBuf,
    db_ip: Option<Ipv4Addr>,
    child: Option<Child>,
    workdir: Option<TempDir>,
    version: String,
    verbose: bool,
}

impl State {
    async fn new(path: PathBuf, default_conf: PathBuf, verbose: bool) -> Self {
        let version = String::from_utf8_lossy(
            &Command::new(&path)
                .arg("--version")
                .output()
                .await
                .expect("db: State::new: failed to execute scylla")
                .stdout,
        )
        .trim()
        .to_string();

        Self {
            path,
            default_conf,
            version,
            db_ip: None,
            child: None,
            workdir: None,
            verbose,
        }
    }
}

async fn process(msg: ScyllaCluster, state: &mut State) {
    match msg {
        ScyllaCluster::Version { tx } => {
            tx.send(state.version.clone())
                .expect("process ScyllaCluster::Version: failed to send a response");
        }

        ScyllaCluster::Start {
            vs_uri,
            db_ip,
            conf,
        } => {
            start(vs_uri, db_ip, conf, state).await;
        }

        ScyllaCluster::Stop => {
            stop(state).await;
        }

        ScyllaCluster::WaitForReady { tx } => {
            tx.send(wait_for_ready(state).await)
                .expect("process ScyllaCluster::WaitForReady: failed to send a response");
        }

        ScyllaCluster::Up { vs_uri, conf } => {
            up(vs_uri, conf, state).await;
        }

        ScyllaCluster::Down => {
            down(state).await;
        }
    }
}

async fn run_cluster(
    vs_uri: &String,
    db_ip: &Ipv4Addr,
    conf: &Option<Vec<u8>>,
    path: &Path,
    state: &mut State,
) {
    let conf = if let Some(conf) = conf {
        let conf_path = path.join("scylla.conf");
        fs::write(&conf_path, conf)
            .await
            .expect("start: failed to write scylla config");
        conf_path
    } else {
        state.default_conf.clone()
    };
    let mut cmd = Command::new(&state.path);
    if !state.verbose {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }
    state.child = Some(
        cmd.arg("--overprovisioned")
            .arg("--options-file")
            .arg(&conf)
            .arg("--workdir")
            .arg(path)
            .arg("--listen-address")
            .arg(db_ip.to_string())
            .arg("--rpc-address")
            .arg(db_ip.to_string())
            .arg("--api-address")
            .arg(db_ip.to_string())
            .arg("--seed-provider-parameters")
            .arg(format!("seeds={db_ip}"))
            .arg("--vector-store-primary-uri")
            .arg(vs_uri)
            .arg("--developer-mode")
            .arg("true")
            .arg("--smp")
            .arg("1")
            .arg("--default-log-level")
            .arg("trace")
            .spawn()
            .expect("start: failed to spawn scylladb"),
    );
}

async fn start(vs_uri: String, db_ip: Ipv4Addr, conf: Option<Vec<u8>>, state: &mut State) {
    let workdir = TempDir::new().expect("start: failed to create temporary directory for scylladb");
    run_cluster(&vs_uri, &db_ip, &conf, workdir.path(), state).await;
    state.workdir = Some(workdir);
    state.db_ip = Some(db_ip);
}

async fn stop(state: &mut State) {
    let Some(mut child) = state.child.take() else {
        return;
    };
    child
        .start_kill()
        .expect("stop: failed to send SIGTERM to scylladb process");
    child
        .wait()
        .await
        .expect("stop: failed to wait for scylladb process to exit");
    state.child = None;
    state.workdir = None;
    state.db_ip = None;
}

async fn down(state: &mut State) {
    let Some(mut child) = state.child.take() else {
        return;
    };
    child
        .start_kill()
        .expect("stop: failed to send SIGTERM to scylladb process");
    child
        .wait()
        .await
        .expect("stop: failed to wait for scylladb process to exit");
    state.child = None;
}

/// Waits for ScyllaDB to be ready by checking the nodetool status.
async fn wait_for_ready(state: &State) -> bool {
    let Some(db_ip) = state.db_ip else {
        return false;
    };
    let mut cmd = Command::new(&state.path);
    cmd.arg("nodetool")
        .arg("-h")
        .arg(db_ip.to_string())
        .arg("status");

    loop {
        if String::from_utf8_lossy(
            &cmd.output()
                .await
                .expect("start: failed to run nodetool")
                .stdout,
        )
        .lines()
        .any(|line| line.starts_with(&format!("UN {db_ip}")))
        {
            return true;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

async fn up(vs_uri: String, conf: Option<Vec<u8>>, state: &mut State) {
    let db_ip = state.db_ip.expect("State should have DB IP");
    let path = state
        .workdir
        .as_ref()
        .expect("State should have workdir")
        .path()
        .to_path_buf();

    run_cluster(&vs_uri, &db_ip, &conf, &path, state).await;
}
