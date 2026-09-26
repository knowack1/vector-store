/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

mod actor;
mod bare_word;
mod consolidation;
mod factory;
mod tantivy;
mod term_top_k;

use crate::FtsTuning;
use crate::memory::Memory;
use crate::worker::Worker;
pub(crate) use actor::FtsIndex;
pub(crate) use actor::FtsIndexExt;
pub(crate) use factory::FtsIndexConfiguration;
pub(crate) use factory::FtsIndexFactory;
pub(crate) use factory::FtsSearcher;
pub(crate) use tantivy::QueryError;
use tantivy::TantivyIndexFactory;
use tokio::sync::mpsc;

pub(crate) fn new_fts_index_factory_tantivy(
    worker: async_channel::Sender<Worker>,
    memory: mpsc::Sender<Memory>,
    tuning: FtsTuning,
) -> Box<dyn FtsIndexFactory + Send + Sync> {
    Box::new(TantivyIndexFactory::new(worker, memory, tuning))
}
