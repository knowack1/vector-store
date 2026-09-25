/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

use std::num::NonZeroUsize;

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

    fn target(segments: usize) -> NonZeroUsize {
        NonZeroUsize::new(segments).unwrap()
    }

    fn sized(docs: &[u64]) -> Vec<(usize, u64)> {
        docs.iter().copied().enumerate().collect()
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
