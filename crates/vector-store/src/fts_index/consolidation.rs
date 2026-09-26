/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;

use tantivy::index::SegmentId;
use tantivy::index::SegmentMeta;
use tantivy::indexer::MergeCandidate;
use tantivy::indexer::MergePolicy;

/// The merge policy while consolidation runs: it starts no merges, and remembers the
/// committed segments tantivy last offered it, which are the committed segments no running
/// merge holds.
///
/// Tantivy asks the policy twice per decision, after every commit and every merge end: about
/// the uncommitted segments first and the committed ones second. It takes the policy once per
/// decision, so a policy set between two decisions sees whole pairs.
#[derive(Clone, Debug, Default)]
pub(super) struct ConsolidationPolicy {
    offers: Arc<Mutex<Offers>>,
}

#[derive(Debug, Default)]
struct Offers {
    calls: u64,
    committed: Vec<SegmentId>,
}

impl ConsolidationPolicy {
    /// The committed segments no merge held when tantivy last offered them; none before
    /// its first decision.
    pub(super) fn free_segments(&self) -> Vec<SegmentId> {
        self.offers.lock().unwrap().committed.clone()
    }
}

impl MergePolicy for ConsolidationPolicy {
    fn compute_merge_candidates(&self, segments: &[SegmentMeta]) -> Vec<MergeCandidate> {
        let mut offers = self.offers.lock().unwrap();
        if offers.calls % 2 == 1 {
            offers.committed = segments.iter().map(|meta| meta.id()).collect();
        }
        offers.calls += 1;
        Vec::new()
    }
}

/// What consolidation does next.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step<M> {
    /// The index is at or below the target.
    Done,
    /// A merge consolidation did not start holds `busy` of the segments.
    Wait {
        busy: usize,
    },
    Merge(M),
}

impl<M> Step<M> {
    pub(super) fn map_merge<N>(self, f: impl FnOnce(M) -> N) -> Step<N> {
        match self {
            Step::Done => Step::Done,
            Step::Wait { busy } => Step::Wait { busy },
            Step::Merge(merge) => Step::Merge(f(merge)),
        }
    }
}

/// Plans the next step toward `target` over `segments`, given as `(id, live docs)`, of which
/// only those in `free` are in no running merge.
///
/// It waits while any segment is in another merge rather than planning around it. A merge
/// that takes a segment another merge also holds fails, but only after doing all of its
/// work; and a merge beside another one needs the transient memory of both.
pub(super) fn next_step<T: Copy + PartialEq>(
    segments: &[(T, u64)],
    free: &[T],
    target: NonZeroUsize,
) -> Step<Vec<T>> {
    if segments.len() <= target.get() {
        return Step::Done;
    }
    let busy = segments.iter().filter(|(id, _)| !free.contains(id)).count();
    if busy > 0 {
        return Step::Wait { busy };
    }
    next_merge(segments, target).map_or(Step::Done, Step::Merge)
}

/// Picks the next merge that moves `segments`, given as `(id, live docs)`, toward `target`
/// segments, or `None` once there are at most `target`.
///
/// It merges the smallest segments, and never more of them than it takes to reach `target`.
/// It stops adding segments once the merge would outgrow an even `1 / target` share of the
/// index, because an in-RAM merge holds its output next to its inputs until the reader lets
/// go of them: bounding each merge bounds that transient memory. It still takes at least two
/// segments, so every merge brings the count down.
pub(super) fn next_merge<T: Copy>(segments: &[(T, u64)], target: NonZeroUsize) -> Option<Vec<T>> {
    let target = target.get();
    if segments.len() <= target {
        return None;
    }
    let even_share = total_docs(segments).div_ceil(target as u64);
    let max_inputs = segments.len() - target + 1;
    Some(
        smallest_first(segments)
            .into_iter()
            .take(max_inputs)
            .scan(0, |merged_docs, (id, docs)| {
                *merged_docs += docs;
                Some((id, *merged_docs))
            })
            .enumerate()
            .take_while(|(taken, (_, merged_docs))| *taken < 2 || *merged_docs <= even_share)
            .map(|(_, (id, _))| id)
            .collect(),
    )
}

fn total_docs<T>(segments: &[(T, u64)]) -> u64 {
    segments.iter().map(|(_, docs)| docs).sum()
}

fn smallest_first<T: Copy>(segments: &[(T, u64)]) -> Vec<(T, u64)> {
    let mut sorted = segments.to_vec();
    sorted.sort_by_key(|(_, docs)| *docs);
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;
    use tantivy::schema::Schema;

    fn target(segments: usize) -> NonZeroUsize {
        NonZeroUsize::new(segments).unwrap()
    }

    fn sized(docs: &[u64]) -> Vec<(usize, u64)> {
        docs.iter().copied().enumerate().collect()
    }

    fn metas(count: usize) -> Vec<SegmentMeta> {
        let index = tantivy::Index::create_in_ram(Schema::builder().build());
        (0..count)
            .map(|_| index.new_segment_meta(SegmentId::generate_random(), 10))
            .collect()
    }

    fn ids(metas: &[SegmentMeta]) -> Vec<SegmentId> {
        metas.iter().map(|meta| meta.id()).collect()
    }

    #[test]
    fn policy_merges_nothing_and_keeps_the_last_committed_offer() {
        let policy = ConsolidationPolicy::default();
        let (uncommitted, committed, later) = (metas(1), metas(2), metas(3));
        assert!(policy.free_segments().is_empty());

        for offer in [&uncommitted, &committed, &uncommitted, &later] {
            assert!(policy.compute_merge_candidates(offer).is_empty());
        }

        assert_eq!(policy.free_segments(), ids(&later));
    }

    #[test]
    fn plan_is_done_at_the_target_even_while_a_segment_is_in_a_merge() {
        assert_eq!(next_step(&sized(&[5, 1]), &[], target(2)), Step::Done);
    }

    #[test]
    fn plan_waits_while_any_segment_is_in_another_merge() {
        let segments = sized(&[5, 1, 9, 2]);

        assert_eq!(
            next_step(&segments, &[0, 1, 3], target(2)),
            Step::Wait { busy: 1 }
        );
    }

    #[test]
    fn plan_merges_once_every_segment_is_free() {
        let segments = sized(&[100, 1, 2, 3, 50]);

        assert_eq!(
            next_step(&segments, &[0, 1, 2, 3, 4], target(3)),
            Step::Merge(vec![1, 2, 3])
        );
    }

    #[test]
    fn no_merge_at_or_below_the_target() {
        assert_eq!(next_merge(&sized(&[5, 1, 9]), target(3)), None);
        assert_eq!(next_merge(&sized(&[5, 1]), target(3)), None);
        assert_eq!(next_merge::<usize>(&[], target(1)), None);
    }

    #[test]
    fn merges_the_smallest_segments_and_no_more_than_needed() {
        let merge = next_merge(&sized(&[100, 1, 2, 3, 50]), target(3));

        assert_eq!(merge, Some(vec![1, 2, 3]));
    }

    #[test]
    fn stops_at_an_even_share_of_the_index() {
        let merge = next_merge(&sized(&[10, 10, 10, 10, 100, 100]), target(2));

        assert_eq!(merge, Some(vec![0, 1, 2, 3]));
    }

    #[test]
    fn always_merges_at_least_two_segments() {
        let merge = next_merge(&sized(&[60, 70, 80]), target(2));

        assert_eq!(merge, Some(vec![0, 1]));
    }

    #[test]
    fn empty_segments_go_first() {
        let merge = next_merge(&sized(&[40, 0, 30, 0]), target(3));

        assert_eq!(merge, Some(vec![1, 3]));
    }

    #[test]
    fn repeated_merges_reach_the_target() {
        let mut segments = sized(&[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 3, 5, 7]);
        let mut rounds = 0;
        while let Some(merge) = next_merge(&segments, target(4)) {
            let merged_docs = segments
                .iter()
                .filter(|(id, _)| merge.contains(id))
                .map(|(_, docs)| docs)
                .sum();
            segments.retain(|(id, _)| !merge.contains(id));
            segments.push((100 + rounds, merged_docs));
            rounds += 1;
        }

        assert_eq!(segments.len(), 4);
        assert_eq!(total_docs(&segments), 2062);
    }
}
