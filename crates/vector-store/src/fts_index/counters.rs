/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

//! Observation-only counters for one full-text index: they record what the writer and
//! tantivy's merge policy did, and never change what either does.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tantivy::index::SegmentMeta;
use tantivy::indexer::LogMergePolicy;
use tantivy::indexer::MergeCandidate;
use tantivy::indexer::MergePolicy;

#[derive(Debug, Default)]
pub(crate) struct IndexCounters {
    commits: AtomicU64,
    merges_started: AtomicU64,
}

impl IndexCounters {
    pub(crate) fn record_commit(&self) {
        self.commits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn commits(&self) -> u64 {
        self.commits.load(Ordering::Relaxed)
    }

    pub(crate) fn merges_started(&self) -> u64 {
        self.merges_started.load(Ordering::Relaxed)
    }
}

/// Tantivy's default merge policy, unchanged, counting the merges it asks the writer to start.
#[derive(Debug)]
pub(crate) struct CountingMergePolicy {
    inner: LogMergePolicy,
    counters: Arc<IndexCounters>,
}

impl CountingMergePolicy {
    pub(crate) fn new(counters: Arc<IndexCounters>) -> Self {
        Self {
            inner: LogMergePolicy::default(),
            counters,
        }
    }
}

impl MergePolicy for CountingMergePolicy {
    fn compute_merge_candidates(&self, segments: &[SegmentMeta]) -> Vec<MergeCandidate> {
        let candidates = self.inner.compute_merge_candidates(segments);
        self.counters
            .merges_started
            .fetch_add(candidates.len() as u64, Ordering::Relaxed);
        candidates
    }
}
