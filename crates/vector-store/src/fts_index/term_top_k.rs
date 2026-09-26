/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

//! Top-k search for a query that is a single term, looking the term up once per segment.
//!
//! Tantivy's `TermQuery` finds the term in every segment's term dictionary twice: once
//! for the BM25 document frequency and again to open the postings. Between the two it
//! also opens the segment's inverted index three times and builds a boxed scorer and a
//! top-k buffer per segment. This search keeps the term info of the first lookup and
//! scores the postings straight from it.
//!
//! The hits and their scores are the ones `TopDocs::with_limit(k).order_by_score()`
//! returns for the `TermQuery`, down to ties and to the documents its block-max pruning
//! may skip: the per-segment pruning and both top-k stages follow tantivy's rules.
//! Each segment runs tantivy's own `block_wand_single_scorer`, which moves past a block
//! whose maximum score cannot beat the threshold without decoding it.

use std::cmp::Ordering;
use std::sync::Arc;

use tantivy::DocAddress;
use tantivy::DocId;
use tantivy::InvertedIndexReader;
use tantivy::Score;
use tantivy::Searcher;
use tantivy::SegmentOrdinal;
use tantivy::SegmentReader;
use tantivy::Term;
use tantivy::collector::TopNComputer;
use tantivy::collector::sort_key::NaturalComparator;
use tantivy::fieldnorm::FieldNormReader;
use tantivy::postings::TermInfo;
use tantivy::query::Bm25Weight;
use tantivy::query::TermScorer;
use tantivy::query::block_wand_single_scorer;
use tantivy::schema::IndexRecordOption;

/// Whether `field` of `searcher`'s schema records term frequencies, which BM25 scores
/// the postings with.
pub(super) fn supports(searcher: &Searcher, field: tantivy::schema::Field) -> bool {
    searcher
        .schema()
        .get_field_entry(field)
        .field_type()
        .get_index_record_option()
        .is_some_and(IndexRecordOption::has_freq)
}

/// The `limit` best hits of `term`, best first.
pub(super) fn search(
    searcher: &Searcher,
    term: &Term,
    limit: usize,
) -> tantivy::Result<Vec<(Score, DocAddress)>> {
    let lookup = TermLookup::new(searcher, term)?;
    if lookup.doc_freq == 0 || limit == 0 {
        return Ok(Vec::new());
    }
    let bm25 = lookup.bm25_weight();
    let mut merged = TopNComputer::new_with_comparator(limit, NaturalComparator);
    for segment in &lookup.segments {
        for (score, doc) in segment_top_k(segment, term, &bm25, limit)? {
            merged.push(score, DocAddress::new(segment.ord, doc));
        }
    }
    Ok(merged
        .into_sorted_vec()
        .into_iter()
        .map(|hit| (hit.sort_key, hit.doc))
        .collect())
}

/// A segment that holds the term, with the term's postings location in it.
struct SegmentTerm<'a> {
    ord: SegmentOrdinal,
    reader: &'a SegmentReader,
    inverted_index: Arc<InvertedIndexReader>,
    term_info: TermInfo,
}

/// The BM25 statistics of one term over the searcher, and the segments holding it.
struct TermLookup<'a> {
    segments: Vec<SegmentTerm<'a>>,
    doc_freq: u64,
    total_num_tokens: u64,
    total_num_docs: u64,
}

impl<'a> TermLookup<'a> {
    fn new(searcher: &'a Searcher, term: &Term) -> tantivy::Result<Self> {
        let mut lookup = Self {
            segments: Vec::new(),
            doc_freq: 0,
            total_num_tokens: 0,
            total_num_docs: 0,
        };
        for (ord, reader) in searcher.segment_readers().iter().enumerate() {
            lookup.add_segment(ord as SegmentOrdinal, reader, term)?;
        }
        Ok(lookup)
    }

    fn add_segment(
        &mut self,
        ord: SegmentOrdinal,
        reader: &'a SegmentReader,
        term: &Term,
    ) -> tantivy::Result<()> {
        let inverted_index = reader.inverted_index(term.field())?;
        self.total_num_tokens += inverted_index.total_num_tokens();
        self.total_num_docs += u64::from(reader.max_doc());
        if let Some(term_info) = inverted_index.get_term_info(term)? {
            self.doc_freq += u64::from(term_info.doc_freq);
            self.segments.push(SegmentTerm {
                ord,
                reader,
                inverted_index,
                term_info,
            });
        }
        Ok(())
    }

    /// The weight `Bm25Weight::for_terms` computes for the term from the same statistics.
    fn bm25_weight(&self) -> Bm25Weight {
        let average_fieldnorm = self.total_num_tokens as Score / self.total_num_docs as Score;
        Bm25Weight::for_one_term_without_explain(
            self.doc_freq,
            self.total_num_docs,
            average_fieldnorm,
        )
    }
}

/// The segment's best hits, unordered, as tantivy's block-max WAND over a single term
/// collects them, with the deleted-document filter of `TopDocs`' pruning callback.
fn segment_top_k(
    segment: &SegmentTerm,
    term: &Term,
    bm25: &Bm25Weight,
    limit: usize,
) -> tantivy::Result<Vec<(Score, DocId)>> {
    let scorer = term_scorer(segment, term, bm25)?;
    let alive = segment.reader.alive_bitset();
    let mut top_k = SegmentTopK::new(limit);
    block_wand_single_scorer(scorer, Score::MIN, &mut |doc, score| {
        if alive.is_none_or(|alive| alive.is_alive(doc)) {
            top_k.push(score, doc);
        }
        top_k.threshold()
    });
    Ok(top_k.into_vec())
}

/// The scorer `TermWeight` builds for the term, over the postings of the segment's
/// single term lookup.
fn term_scorer(
    segment: &SegmentTerm,
    term: &Term,
    bm25: &Bm25Weight,
) -> tantivy::Result<TermScorer> {
    let fieldnorms = fieldnorm_reader(segment.reader, term)?;
    let postings = segment
        .inverted_index
        .read_postings_from_terminfo(&segment.term_info, IndexRecordOption::WithFreqs)?;
    Ok(TermScorer::new(postings, fieldnorms, bm25.clone()))
}

/// The field norms `TermWeight` scores with: the segment's, or a constant 1 when the
/// segment has none for the field.
fn fieldnorm_reader(reader: &SegmentReader, term: &Term) -> tantivy::Result<FieldNormReader> {
    Ok(reader
        .fieldnorms_readers()
        .get_field(term.field())?
        .unwrap_or_else(|| FieldNormReader::constant(reader.max_doc(), 1)))
}

/// Tantivy's `TopNComputer` for one segment, down to the threshold it exposes to the
/// pruning, which the public type keeps private.
///
/// The buffer holds up to twice `limit` hits. When it is full, it keeps the best `limit`
/// and the score of the next best becomes the threshold a hit has to beat.
struct SegmentTopK {
    limit: usize,
    capacity: usize,
    buffer: Vec<(Score, DocId)>,
    threshold: Option<Score>,
}

impl SegmentTopK {
    fn new(limit: usize) -> Self {
        let capacity = limit.max(1) * 2;
        Self {
            limit,
            capacity,
            buffer: Vec::with_capacity(capacity),
            threshold: None,
        }
    }

    fn threshold(&self) -> Score {
        self.threshold.unwrap_or(Score::MIN)
    }

    fn push(&mut self, score: Score, doc: DocId) {
        if self.buffer.len() == self.capacity {
            self.threshold = Some(self.truncate());
        }
        self.buffer.push((score, doc));
    }

    fn truncate(&mut self) -> Score {
        let (_, next_best, _) = self.buffer.select_nth_unstable_by(self.limit, best_first);
        let threshold = next_best.0;
        self.buffer.truncate(self.limit);
        threshold
    }

    fn into_vec(mut self) -> Vec<(Score, DocId)> {
        if self.buffer.len() > self.limit {
            self.truncate();
        }
        self.buffer
    }
}

/// Tantivy's top-k order: higher score first, then lower doc id.
fn best_first(lhs: &(Score, DocId), rhs: &(Score, DocId)) -> Ordering {
    rhs.0
        .partial_cmp(&lhs.0)
        .unwrap_or(Ordering::Equal)
        .then_with(|| lhs.1.cmp(&rhs.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tantivy::Index;
    use tantivy::IndexWriter;
    use tantivy::TantivyDocument;
    use tantivy::collector::TopDocs;
    use tantivy::indexer::NoMergePolicy;
    use tantivy::query::TermQuery;
    use tantivy::schema::FAST;
    use tantivy::schema::Field;
    use tantivy::schema::INDEXED;
    use tantivy::schema::Schema;
    use tantivy::schema::TEXT;

    const VOCABULARY: usize = 12;
    const LIMITS: [usize; 7] = [1, 2, 3, 5, 10, 64, 1000];
    const BLOCK: usize = 128;
    const STRONG_EVERY: usize = 1000;
    const PRUNABLE_WORDS: [&str; 2] = ["common", "filler"];

    /// Deterministic xorshift, so a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    struct Corpus {
        index: Index,
        body: Field,
        id: Field,
    }

    impl Corpus {
        fn new() -> Self {
            let mut schema = Schema::builder();
            let id = schema.add_u64_field("id", INDEXED | FAST);
            let body = schema.add_text_field("body", TEXT);
            Self {
                index: Index::create_in_ram(schema.build()),
                body,
                id,
            }
        }

        fn writer(&self) -> IndexWriter {
            let writer = self.index.writer_with_num_threads(1, 15_000_000).unwrap();
            writer.set_merge_policy(Box::new(NoMergePolicy));
            writer
        }

        fn searcher(&self) -> Searcher {
            self.index.reader().unwrap().searcher()
        }

        fn term(&self, word: &str) -> Term {
            Term::from_field_text(self.body, word)
        }
    }

    /// A word of a skewed vocabulary: `w0` is in most documents, `w11` in few.
    fn random_word(rng: &mut Rng) -> String {
        let rank = rng.below(VOCABULARY).min(rng.below(VOCABULARY));
        format!("w{rank}")
    }

    fn random_body(rng: &mut Rng, max_len: usize) -> String {
        (0..1 + rng.below(max_len))
            .map(|_| random_word(rng))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Commits one segment per entry of `max_lens`; the lengths differ per segment so
    /// that each segment's average field norm, which its block maxima are computed
    /// with, is far from the index's.
    fn add_segments(corpus: &Corpus, rng: &mut Rng, docs: u64, max_lens: &[usize]) {
        let mut writer = corpus.writer();
        let mut next_id = 0;
        for &max_len in max_lens {
            for _ in 0..docs {
                let mut doc = TantivyDocument::new();
                doc.add_u64(corpus.id, next_id);
                doc.add_text(corpus.body, random_body(rng, max_len));
                writer.add_document(doc).unwrap();
                next_id += 1;
            }
            writer.commit().unwrap();
        }
    }

    fn delete_every(corpus: &Corpus, step: u64, docs: u64) {
        delete_ids(corpus, (0..docs).step_by(step as usize));
    }

    fn delete_ids(corpus: &Corpus, ids: impl IntoIterator<Item = u64>) {
        let mut writer = corpus.writer();
        for id in ids {
            writer.delete_term(Term::from_field_u64(corpus.id, id));
        }
        writer.commit().unwrap();
    }

    /// The body of document `position` of a posting list of `common` whose blocks the
    /// block-max check mostly prunes: its first block and every `STRONG_EVERY`-th
    /// document repeat `common` in a short body, the others mention it once in a long
    /// one, and its last document scores highest of all.
    fn prunable_body(position: usize, docs: usize) -> String {
        let (repeats, fillers) = if position + 1 == docs {
            (5, 0)
        } else if position % STRONG_EVERY == 0 {
            (3, 1)
        } else if position < BLOCK {
            (2, 2)
        } else {
            (1, 20 + position % 7)
        };
        let words =
            std::iter::repeat_n("common", repeats).chain(std::iter::repeat_n("filler", fillers));
        words.collect::<Vec<_>>().join(" ")
    }

    /// Commits one segment of `prunable_body` documents per entry of `sizes`, and
    /// returns the id of each segment's last, best document.
    fn add_prunable_segments(corpus: &Corpus, sizes: &[usize]) -> Vec<u64> {
        let mut writer = corpus.writer();
        let mut next_id = 0;
        let mut best_ids = Vec::new();
        for &docs in sizes {
            for position in 0..docs {
                let mut doc = TantivyDocument::new();
                doc.add_u64(corpus.id, next_id);
                doc.add_text(corpus.body, prunable_body(position, docs));
                writer.add_document(doc).unwrap();
                next_id += 1;
            }
            best_ids.push(next_id - 1);
            writer.commit().unwrap();
        }
        best_ids
    }

    fn segment_doc_freqs(corpus: &Corpus, word: &str) -> Vec<u32> {
        let term = corpus.term(word);
        corpus
            .searcher()
            .segment_readers()
            .iter()
            .map(|reader| {
                let inverted_index = reader.inverted_index(corpus.body).unwrap();
                inverted_index
                    .get_term_info(&term)
                    .unwrap()
                    .map_or(0, |info| info.doc_freq)
            })
            .collect()
    }

    fn id_of(corpus: &Corpus, address: DocAddress) -> u64 {
        let searcher = corpus.searcher();
        let ids = searcher
            .segment_reader(address.segment_ord)
            .fast_fields()
            .u64("id")
            .unwrap();
        ids.first(address.doc_id).unwrap()
    }

    fn tantivy_top_k(searcher: &Searcher, term: &Term, limit: usize) -> Vec<(Score, DocAddress)> {
        let query = TermQuery::new(term.clone(), IndexRecordOption::WithFreqs);
        searcher
            .search(&query, &TopDocs::with_limit(limit).order_by_score())
            .unwrap()
    }

    fn assert_same_as_tantivy(corpus: &Corpus) {
        assert_same_as_tantivy_for(corpus, (0..VOCABULARY).map(|rank| format!("w{rank}")));
    }

    fn assert_same_as_tantivy_for(corpus: &Corpus, words: impl IntoIterator<Item = String>) {
        let searcher = corpus.searcher();
        for word in words {
            let term = corpus.term(&word);
            for limit in LIMITS {
                assert_eq!(
                    search(&searcher, &term, limit).unwrap(),
                    tantivy_top_k(&searcher, &term, limit),
                    "term {word}, limit {limit}"
                );
            }
        }
    }

    #[test]
    fn matches_tantivy_on_one_segment() {
        let corpus = Corpus::new();
        add_segments(&corpus, &mut Rng(7), 3000, &[30]);
        assert_same_as_tantivy(&corpus);
    }

    #[test]
    fn matches_tantivy_across_segments_of_different_lengths() {
        let corpus = Corpus::new();
        add_segments(&corpus, &mut Rng(11), 1500, &[3, 60, 12, 200, 1]);
        assert_eq!(corpus.searcher().segment_readers().len(), 5);
        assert_same_as_tantivy(&corpus);
    }

    #[test]
    fn matches_tantivy_with_deleted_documents() {
        let corpus = Corpus::new();
        add_segments(&corpus, &mut Rng(13), 1500, &[20, 5, 80]);
        delete_every(&corpus, 3, 4500);
        assert!(
            corpus.searcher().segment_readers()[0]
                .alive_bitset()
                .is_some()
        );
        assert_same_as_tantivy(&corpus);
    }

    fn prunable_words() -> impl Iterator<Item = String> {
        PRUNABLE_WORDS.into_iter().map(String::from)
    }

    #[test]
    fn matches_tantivy_when_most_blocks_are_pruned() {
        let corpus = Corpus::new();
        add_prunable_segments(&corpus, &[40 * BLOCK + 37]);
        assert_same_as_tantivy_for(&corpus, prunable_words());
    }

    #[test]
    fn finds_the_best_hit_in_a_partial_last_block() {
        let corpus = Corpus::new();
        let best_ids = add_prunable_segments(&corpus, &[40 * BLOCK + 37]);
        assert_eq!(
            segment_doc_freqs(&corpus, "common"),
            [40 * BLOCK as u32 + 37]
        );
        let hits = search(&corpus.searcher(), &corpus.term("common"), 1).unwrap();
        assert_eq!(id_of(&corpus, hits[0].1), best_ids[0]);
    }

    #[test]
    fn matches_tantivy_when_most_blocks_are_pruned_across_segments() {
        let corpus = Corpus::new();
        add_prunable_segments(
            &corpus,
            &[30 * BLOCK + 5, 24 * BLOCK, 9 * BLOCK + 127, 3 * BLOCK],
        );
        let doc_freqs = segment_doc_freqs(&corpus, "common");
        assert_eq!(doc_freqs.len(), 4);
        assert!(doc_freqs.iter().any(|&df| df % BLOCK as u32 == 0));
        assert!(doc_freqs.iter().any(|&df| df % BLOCK as u32 != 0));
        assert_same_as_tantivy_for(&corpus, prunable_words());
    }

    #[test]
    fn matches_tantivy_when_pruned_blocks_hold_deleted_documents() {
        let corpus = Corpus::new();
        let sizes = [20 * BLOCK + 77, 16 * BLOCK, 11 * BLOCK + 1];
        let best_ids = add_prunable_segments(&corpus, &sizes);
        let docs = sizes.iter().sum::<usize>() as u64;
        delete_every(&corpus, 5, docs);
        delete_ids(&corpus, best_ids[..2].iter().copied());
        assert!(
            corpus
                .searcher()
                .segment_readers()
                .iter()
                .all(|reader| reader.alive_bitset().is_some())
        );
        assert_same_as_tantivy_for(&corpus, prunable_words());
    }

    #[test]
    fn term_missing_from_every_segment_has_no_hits() {
        let corpus = Corpus::new();
        add_segments(&corpus, &mut Rng(17), 200, &[10, 10]);
        let term = corpus.term("absent");
        assert!(search(&corpus.searcher(), &term, 5).unwrap().is_empty());
    }

    #[test]
    fn empty_index_has_no_hits() {
        let corpus = Corpus::new();
        let term = corpus.term("w0");
        assert!(search(&corpus.searcher(), &term, 5).unwrap().is_empty());
    }

    #[test]
    fn zero_limit_has_no_hits() {
        let corpus = Corpus::new();
        add_segments(&corpus, &mut Rng(19), 200, &[10]);
        let term = corpus.term("w0");
        assert!(search(&corpus.searcher(), &term, 0).unwrap().is_empty());
    }

    #[test]
    fn supports_only_fields_with_term_frequencies() {
        let corpus = Corpus::new();
        let searcher = corpus.searcher();
        assert!(supports(&searcher, corpus.body));
        assert!(!supports(&searcher, corpus.id));
    }
}
