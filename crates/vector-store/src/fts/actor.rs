/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use super::FtsIndex;
use super::FtsMessage;
use crate::IndexKey;
use tokio::sync::mpsc;
use tracing::Instrument;
use tracing::debug;
use tracing::error;
use tracing::error_span;

const CHANNEL_SIZE: usize = 10;

/// Spawns the FTS actor loop and returns a sender for communicating with it.
pub(crate) fn new(index_key: IndexKey) -> anyhow::Result<mpsc::Sender<FtsMessage>> {
    let fts_index = FtsIndex::new()?;
    let (tx, mut rx) = mpsc::channel(CHANNEL_SIZE);

    tokio::spawn(
        async move {
            debug!("starting");

            while let Some(msg) = rx.recv().await {
                handle_message(&fts_index, msg);
            }

            debug!("finished");
        }
        .instrument(error_span!("fts", "{index_key}")),
    );

    Ok(tx)
}

fn handle_message(fts_index: &FtsIndex, msg: FtsMessage) {
    match msg {
        FtsMessage::AddDocument {
            primary_id,
            text_content,
            ..
        } => {
            if let Err(err) = fts_index.add_document(primary_id, &text_content) {
                error!("failed to add document: {err}");
            }
        }
        FtsMessage::RemoveDocument { primary_id, .. } => {
            if let Err(err) = fts_index.remove_document(primary_id) {
                error!("failed to remove document: {err}");
            }
        }
        FtsMessage::Search { query, limit, tx } => {
            let result = fts_index.search(&query, limit);
            let _ = tx.send(result);
        }
        FtsMessage::Count { tx } => {
            let result = fts_index.count();
            let _ = tx.send(result);
        }
    }
}
