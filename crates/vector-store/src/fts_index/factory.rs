/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

use crate::Analyzer;
use crate::IndexKey;
use crate::Limit;
use crate::Positions;
use crate::fts_index::actor::FtsIndex;
use crate::fts_index::actor::FtsSearchR;
use crate::table::Table;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub(crate) struct FtsIndexConfiguration {
    pub key: IndexKey,
    pub analyzer: Analyzer,
    pub positions: Positions,
}

/// Searches an index on the caller's thread.
///
/// A search sees every commit and merge the index has made searchable when it starts.
pub(crate) trait FtsSearch {
    fn search(&self, index_key: &IndexKey, query: &str, limit: Limit) -> FtsSearchR;
}

pub(crate) type FtsSearcher = Arc<dyn FtsSearch + Send + Sync>;

/// The two ways into an index: its searcher runs searches, its actor takes everything else
/// (writes, commits, reloads, counts, highlights and stats).
pub(crate) struct FtsIndexHandles {
    pub(crate) actor: mpsc::Sender<FtsIndex>,
    pub(crate) searcher: FtsSearcher,
}

pub(crate) trait FtsIndexFactory {
    fn create_index(
        &self,
        index: FtsIndexConfiguration,
        table: Arc<RwLock<Table>>,
    ) -> FtsIndexHandles;
}
