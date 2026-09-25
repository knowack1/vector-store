/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::anyhow;
use tantivy::DocAddress;
use tantivy::FutureResult;
use tantivy::IndexWriter;
use tantivy::ReloadPolicy;
use tantivy::Searcher;
use tantivy::SegmentOrdinal;
use tantivy::SegmentReader;
use tantivy::TantivyDocument;
use tantivy::collector::TopDocs;
use tantivy::columnar::Column;
use tantivy::index::SegmentId;
use tantivy::index::SegmentMeta;
use tantivy::indexer::IndexWriterOptions;
use tantivy::indexer::LogMergePolicy;
use tantivy::indexer::MergePolicy;
use tantivy::indexer::NoMergePolicy;
use tantivy::query::BooleanQuery;
use tantivy::query::BoostQuery;
use tantivy::query::Occur;
use tantivy::query::Query;
use tantivy::query::QueryParser;
use tantivy::schema::FAST;
use tantivy::schema::INDEXED;
use tantivy::schema::IndexRecordOption;
use tantivy::schema::Schema;
use tantivy::schema::TextFieldIndexing;
use tantivy::schema::TextOptions;
use tantivy::snippet::SnippetGenerator;
use tantivy::tokenizer::Language;
use tantivy::tokenizer::LowerCaser;
use tantivy::tokenizer::SimpleTokenizer;
use tantivy::tokenizer::Stemmer;
use tantivy::tokenizer::StopWordFilter;
use tantivy::tokenizer::TextAnalyzer;
use tantivy::tokenizer::WhitespaceTokenizer;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Analyzer;
use crate::AsyncInProgress;
use crate::FtsTuning;
use crate::IndexKey;
use crate::Limit;
use crate::Positions;
use crate::fts_index::factory::FtsIndexConfiguration;
use crate::fts_index::factory::FtsIndexFactory;
use crate::memory::Allocate;
use crate::memory::Memory;
use crate::memory::MemoryExt;
use crate::perf;
use crate::table::IndexId;
use crate::table::PrimaryId;
use crate::table::Table;
use crate::table::TableSearch;
use crate::worker::Worker;
use crate::worker::WorkerExt;

use super::actor::FtsHighlightR;
use super::actor::FtsIndex;
use super::actor::FtsSearchR;
use super::actor::FtsStats;
use super::actor::FtsStatsR;
use super::consolidation;

pub(crate) struct TantivyIndexFactory {
    worker: async_channel::Sender<Worker>,
    memory: mpsc::Sender<Memory>,
    tuning: FtsTuning,
}

impl TantivyIndexFactory {
    pub(crate) fn new(
        worker: async_channel::Sender<Worker>,
        memory: mpsc::Sender<Memory>,
        tuning: FtsTuning,
    ) -> Self {
        Self {
            worker,
            memory,
            tuning,
        }
    }
}

impl FtsIndexFactory for TantivyIndexFactory {
    fn create_index(
        &self,
        index: FtsIndexConfiguration,
        table: Arc<RwLock<Table>>,
    ) -> mpsc::Sender<FtsIndex> {
        new(
            index,
            table,
            self.worker.clone(),
            self.memory.clone(),
            COMMIT_INTERVAL,
            MAX_UNCOMMITTED_THRESHOLD,
            self.tuning,
        )
    }
}

struct Writer {
    writer: IndexWriter,
    // In-progress guards for documents written to the writer but not yet committed. They are held
    // here so the index is not reported as caught up (SERVING) until the commit that makes those
    // documents searchable has succeeded.
    uncommitted_docs_in_progress_guards: Vec<AsyncInProgress>,
}

impl Writer {
    fn add_document(
        &mut self,
        doc: TantivyDocument,
        in_progress: AsyncInProgress,
    ) -> tantivy::Result<usize> {
        self.writer.add_document(doc)?;
        self.uncommitted_docs_in_progress_guards.push(in_progress);
        Ok(self.uncommitted_docs())
    }

    fn rm_document(&mut self, term: tantivy::Term, in_progress: AsyncInProgress) -> usize {
        self.writer.delete_term(term);
        self.uncommitted_docs_in_progress_guards.push(in_progress);
        self.uncommitted_docs()
    }

    fn commit(&mut self, reload: impl FnOnce() -> tantivy::Result<()>) -> tantivy::Result<()> {
        self.writer.commit()?;
        reload()?;
        self.uncommitted_docs_in_progress_guards.clear();
        Ok(())
    }

    fn uncommitted_docs(&self) -> usize {
        self.uncommitted_docs_in_progress_guards.len()
    }

    fn has_uncommitted_docs(&self) -> bool {
        !self.uncommitted_docs_in_progress_guards.is_empty()
    }
}

struct IndexState {
    index: tantivy::Index,
    writer: RwLock<Writer>,
    reader: tantivy::IndexReader,
    primary_ids: PrimaryIdColumns,
    schema: Schema,
    consolidating: AtomicBool,
}

const COMMIT_INTERVAL: Duration = Duration::from_secs(3);
const MAX_UNCOMMITTED_THRESHOLD: usize = 10_000;

impl IndexState {
    fn new(analyzer: Analyzer, positions: Positions, tuning: FtsTuning) -> anyhow::Result<Self> {
        let tokenizer = analyzer.to_string();
        let schema = build_schema(&tokenizer, positions);
        let index = tantivy::Index::create_in_ram(schema.clone());
        index
            .tokenizers()
            .register(&tokenizer, build_token_pipeline(analyzer)?);
        let options = IndexWriterOptions::builder()
            .num_worker_threads(perf::num_workers().into())
            .memory_budget_per_thread(tuning.writer_memory_bytes)
            .build();
        info!(
            "fts: index writer using {} threads, {} MB buffer per thread",
            perf::num_workers(),
            tuning.writer_memory_bytes / 1_000_000
        );
        let writer = index
            .writer_with_options(options)
            .map_err(|e| anyhow!("fts: failed to create writer: {e}"))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| anyhow!("fts: failed to create reader: {e}"))?;
        Ok(Self {
            index,
            writer: RwLock::new(Writer {
                writer,
                uncommitted_docs_in_progress_guards: Vec::new(),
            }),
            reader,
            primary_ids: PrimaryIdColumns::default(),
            schema,
            consolidating: AtomicBool::new(false),
        })
    }
}

fn stop_words(language: Language) -> anyhow::Result<StopWordFilter> {
    StopWordFilter::new(language)
        .ok_or_else(|| anyhow!("fts: stop words unavailable for {language:?}"))
}

/// The same token pipeline runs over the indexed documents and over the queries,
/// so both sides produce matching tokens.
fn build_token_pipeline(analyzer: Analyzer) -> anyhow::Result<TextAnalyzer> {
    // The language analyzers share the pipeline of `standard` and add the stop
    // words and the stemming of their own language.
    let language = match analyzer {
        // Splits on whitespace only, keeping punctuation and letter case.
        Analyzer::Whitespace => {
            return Ok(TextAnalyzer::builder(WhitespaceTokenizer::default()).build());
        }
        // Splits on non-alphanumeric characters and lowercases, nothing more.
        Analyzer::Simple => {
            return Ok(TextAnalyzer::builder(SimpleTokenizer::default())
                .filter(LowerCaser)
                .build());
        }
        // Removes English stop words, but does not stem.
        Analyzer::Standard => {
            return Ok(TextAnalyzer::builder(SimpleTokenizer::default())
                .filter(LowerCaser)
                .filter(stop_words(Language::English)?)
                .build());
        }
        Analyzer::English => Language::English,
        Analyzer::German => Language::German,
        Analyzer::French => Language::French,
        Analyzer::Spanish => Language::Spanish,
        Analyzer::Italian => Language::Italian,
        Analyzer::Portuguese => Language::Portuguese,
        Analyzer::Russian => Language::Russian,
    };
    Ok(TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .filter(stop_words(language)?)
        .filter(Stemmer::new(language))
        .build())
}

fn body_text_options(tokenizer: &str, positions: Positions) -> TextOptions {
    // Positions are what phrase queries match on.
    // Dropping them makes the index smaller at the cost of rejecting phrase queries against it.
    let index_option = if *positions.as_ref() {
        IndexRecordOption::WithFreqsAndPositions
    } else {
        IndexRecordOption::WithFreqs
    };
    let indexing = TextFieldIndexing::default()
        .set_tokenizer(tokenizer)
        .set_index_option(index_option);
    TextOptions::default().set_indexing_options(indexing)
}

fn build_schema(tokenizer: &str, positions: Positions) -> Schema {
    let mut schema_builder = Schema::builder();
    // INDEXED serves the delete-by-term of removals, FAST the hit-to-id lookup of searches.
    schema_builder.add_u64_field("primary_id", INDEXED | FAST);
    schema_builder.add_text_field("body", body_text_options(tokenizer, positions));
    schema_builder.build()
}

fn create_doc(schema: &Schema, primary_id: PrimaryId, document: &str) -> TantivyDocument {
    let primary_id_field = schema.get_field("primary_id").unwrap();
    let body_field = schema.get_field("body").unwrap();

    let mut doc = TantivyDocument::new();
    doc.add_u64(primary_id_field, u64::from(primary_id));
    doc.add_text(body_field, document);
    doc
}

fn commit(state: &IndexState, key: &IndexKey) {
    let result = state
        .writer
        .write()
        .unwrap()
        .commit(|| reload_reader(state, key, "commit"));
    if let Err(err) = result {
        error!("fts: failed to commit for {key}: {err}");
    }
}

fn reload_reader(state: &IndexState, key: &IndexKey, cause: &str) -> tantivy::Result<()> {
    state.reader.reload()?;
    state.primary_ids.refresh(&state.reader)?;
    log_served_segments(key, cause, &state.reader.searcher());
    Ok(())
}

/// Logs the segments a reload made searchable, a count that does not depend on
/// when the `fts_segment_count` gauge was last refreshed.
fn log_served_segments(key: &IndexKey, cause: &str, searcher: &Searcher) {
    let max_docs: Vec<u32> = searcher
        .segment_readers()
        .iter()
        .map(|segment| segment.max_doc())
        .collect();
    info!(
        "fts: reader reloaded after {cause} for {key}: {} segments, max_doc sum {} min {} max {}",
        max_docs.len(),
        max_docs.iter().copied().map(u64::from).sum::<u64>(),
        max_docs.iter().min().unwrap_or(&0),
        max_docs.iter().max().unwrap_or(&0),
    );
}

/// Whether the reader still serves a segment set that background merges have replaced.
///
/// The reader is reloaded only on commit, so a merge finishing after the last commit
/// would otherwise stay invisible until the next write.
fn reader_misses_merges(state: &IndexState) -> tantivy::Result<bool> {
    let searchable: BTreeSet<_> = state.index.searchable_segment_ids()?.into_iter().collect();
    let served: BTreeSet<_> = state
        .reader
        .searcher()
        .segment_readers()
        .iter()
        .map(|segment| segment.segment_id())
        .collect();
    Ok(served != searchable)
}

fn reload_after_merges(state: &IndexState, key: &IndexKey) {
    let result = reader_misses_merges(state).and_then(|stale| {
        if stale {
            reload_reader(state, key, "background merges")
        } else {
            Ok(())
        }
    });
    if let Err(err) = result {
        error!("fts: failed to reload reader after merges for {key}: {err}");
    }
}

/// Merge attempts that consolidation allows beyond the fewest it needs to reach its target.
/// A merge fails harmlessly when a background merge, already running when consolidation
/// began, replaces one of its input segments first.
const MAX_FAILED_CONSOLIDATION_MERGES: usize = 3;

fn start_consolidation(
    state: &Arc<IndexState>,
    key: IndexKey,
    target: NonZeroUsize,
    allocate: watch::Receiver<Allocate>,
) -> Option<tokio::task::JoinHandle<()>> {
    if state.consolidating.swap(true, Ordering::AcqRel) {
        debug!("fts: consolidation of {key} is already running");
        return None;
    }
    Some(tokio::spawn(consolidate(
        Arc::downgrade(state),
        key,
        target,
        allocate,
    )))
}

/// Merges the index down to at most `target` segments, one bounded merge at a time.
///
/// Tantivy's merge policy is off meanwhile, so it cannot start merges that race ours for
/// the same segments. Weak, so that dropping the index stops the consolidation.
async fn consolidate(
    state: Weak<IndexState>,
    key: IndexKey,
    target: NonZeroUsize,
    allocate: watch::Receiver<Allocate>,
) {
    info!("fts: consolidating {key} to at most {target} segments");
    let Some(excess) = on_state(&state, move |state| {
        set_merge_policy(state, Box::new(NoMergePolicy));
        searchable_segment_count(state).saturating_sub(target.get())
    })
    .await
    else {
        return;
    };
    merge_down(&state, &key, target, &allocate, excess).await;
    on_state(&state, move |state| finish_consolidation(state, &key)).await;
}

async fn merge_down(
    state: &Weak<IndexState>,
    key: &IndexKey,
    target: NonZeroUsize,
    allocate: &watch::Receiver<Allocate>,
    excess: usize,
) {
    for _ in 0..excess + MAX_FAILED_CONSOLIDATION_MERGES {
        if *allocate.borrow() == Allocate::Cannot {
            warn!("fts: stopping consolidation of {key}: not enough memory");
            return;
        }
        let Some(merge) = on_state(state, move |state| start_next_merge(state, target)).await
        else {
            return;
        };
        match merge {
            Ok(Some(merge)) => await_merge(state, key, merge).await,
            Ok(None) => return,
            Err(err) => {
                error!("fts: failed to plan a consolidation merge for {key}: {err}");
                return;
            }
        }
    }
}

/// Reloads after each merge rather than on the next tick, so the reader releases the
/// merged-away segments before the next merge needs memory for its own output.
async fn await_merge(
    state: &Weak<IndexState>,
    key: &IndexKey,
    merge: FutureResult<Option<SegmentMeta>>,
) {
    if let Err(err) = merge.await {
        warn!("fts: consolidation merge for {key} failed: {err}");
        return;
    }
    let key = key.clone();
    on_state(state, move |state| reload_after_merges(state, &key)).await;
}

/// Runs `f` on a blocking thread: the writer lock it may take is held across whole commits.
async fn on_state<R: Send + 'static>(
    state: &Weak<IndexState>,
    f: impl FnOnce(&IndexState) -> R + Send + 'static,
) -> Option<R> {
    let state = state.upgrade()?;
    tokio::task::spawn_blocking(move || f(&state)).await.ok()
}

fn start_next_merge(
    state: &IndexState,
    target: NonZeroUsize,
) -> tantivy::Result<Option<FutureResult<Option<SegmentMeta>>>> {
    let segments: Vec<_> = state
        .index
        .searchable_segment_metas()?
        .iter()
        .map(|meta| (meta.id(), u64::from(meta.num_docs())))
        .collect();
    Ok(consolidation::next_merge(&segments, target)
        .map(|segment_ids| state.writer.write().unwrap().writer.merge(&segment_ids)))
}

fn set_merge_policy(state: &IndexState, policy: Box<dyn MergePolicy>) {
    state.writer.read().unwrap().writer.set_merge_policy(policy);
}

fn searchable_segment_count(state: &IndexState) -> usize {
    state
        .index
        .searchable_segment_ids()
        .map(|ids| ids.len())
        .unwrap_or(0)
}

fn finish_consolidation(state: &IndexState, key: &IndexKey) {
    set_merge_policy(state, Box::new(LogMergePolicy::default()));
    reload_after_merges(state, key);
    state.consolidating.store(false, Ordering::Release);
    info!(
        "fts: consolidation of {key} finished, serving {} segments",
        state.reader.searcher().segment_readers().len()
    );
}

fn handle_add_document(
    state: &IndexState,
    primary_id: PrimaryId,
    document: String,
    in_progress: AsyncInProgress,
) -> usize {
    let doc = create_doc(&state.schema, primary_id, &document);
    let mut writer = state.writer.write().unwrap();
    match writer.add_document(doc, in_progress) {
        Ok(pending) => pending,
        Err(err) => {
            error!("fts: failed to add document {primary_id:?}: {err}");
            writer.uncommitted_docs()
        }
    }
}

fn create_term(schema: &Schema, primary_id: PrimaryId) -> tantivy::Term {
    let primary_id_field = schema.get_field("primary_id").unwrap();
    tantivy::Term::from_field_u64(primary_id_field, u64::from(primary_id))
}

fn handle_remove_document(
    state: &IndexState,
    primary_id: PrimaryId,
    in_progress: AsyncInProgress,
) -> usize {
    let term = create_term(&state.schema, primary_id);
    state.writer.write().unwrap().rm_document(term, in_progress)
}

/// A query-related failure caused by the caller's input (an unparsable query, or a query
/// construct that this endpoint cannot process) rather than an internal/actor failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct QueryError(pub(crate) String);

fn make_query(
    index: &tantivy::Index,
    body_field: tantivy::schema::Field,
    query_str: &str,
) -> anyhow::Result<Box<dyn tantivy::query::Query>> {
    let query_parser = QueryParser::for_index(index, vec![body_field]);
    query_parser
        .parse_query(query_str)
        .map_err(|e| QueryError(format!("fts: failed to parse query: {e}")).into())
}

fn find_partition_id(
    table: &impl TableSearch,
    index_key: &IndexKey,
) -> anyhow::Result<crate::table::PartitionId> {
    let (partition_id, _) = table
        .partition_id(index_key, None)
        .ok_or_else(|| anyhow!("fts: partition id not found for index key {index_key:?}"))?;
    Ok(partition_id)
}

type SegmentColumns = BTreeMap<SegmentId, Column<u64>>;

/// The `primary_id` fast-field column of every segment the reader serves.
///
/// Opening a column reads all of its block headers. Done per query for every segment
/// a query hit, that took a third of the search CPU, so the columns are opened once,
/// when a reader reload changes the served segments.
#[derive(Default)]
struct PrimaryIdColumns {
    refresh: Mutex<()>,
    served: RwLock<Arc<SegmentColumns>>,
    misses: AtomicU64,
}

impl PrimaryIdColumns {
    /// Opens the columns of the segments the reader started serving and drops those of
    /// the segments it no longer serves.
    fn refresh(&self, reader: &tantivy::IndexReader) -> tantivy::Result<()> {
        // Commits and merge reloads run on different workers; serializing their refreshes
        // makes the columns of the newest searcher the ones stored last.
        let _refresh = self.refresh.lock().unwrap();
        let served = served_columns(&reader.searcher(), &self.snapshot())?;
        *self.served.write().unwrap() = Arc::new(served);
        Ok(())
    }

    fn snapshot(&self) -> Arc<SegmentColumns> {
        Arc::clone(&self.served.read().unwrap())
    }

    fn record_miss(&self, segment_id: SegmentId) {
        let misses = self.misses.fetch_add(1, Ordering::Relaxed) + 1;
        debug!(
            "fts: primary_id column of segment {segment_id} not cached, opened for one query \
             ({misses} misses so far)"
        );
    }
}

fn served_columns(searcher: &Searcher, cached: &SegmentColumns) -> tantivy::Result<SegmentColumns> {
    searcher
        .segment_readers()
        .iter()
        .map(|segment| {
            let segment_id = segment.segment_id();
            let column = match cached.get(&segment_id) {
                Some(column) => column.clone(),
                None => open_primary_id_column(segment)?,
            };
            Ok((segment_id, column))
        })
        .collect()
}

fn open_primary_id_column(segment: &SegmentReader) -> tantivy::Result<Column<u64>> {
    segment.fast_fields().u64("primary_id")
}

/// Resolves search hits to their primary ids through the cached `primary_id` columns.
///
/// Reading the id from the column avoids decompressing a doc-store block per hit.
/// A searcher taken between a reader reload and the refresh of the columns that follows
/// it can serve a segment the cache does not hold; that segment's column is opened at
/// most once per query.
struct HitPrimaryIds<'a> {
    searcher: &'a Searcher,
    columns: &'a PrimaryIdColumns,
    cached: Arc<SegmentColumns>,
    opened: BTreeMap<SegmentOrdinal, Column<u64>>,
}

impl<'a> HitPrimaryIds<'a> {
    fn new(searcher: &'a Searcher, columns: &'a PrimaryIdColumns) -> Self {
        Self {
            searcher,
            columns,
            cached: columns.snapshot(),
            opened: BTreeMap::new(),
        }
    }

    fn primary_id(&mut self, doc_address: DocAddress) -> anyhow::Result<PrimaryId> {
        self.column(doc_address.segment_ord)?
            .first(doc_address.doc_id)
            .map(PrimaryId::from)
            .ok_or_else(|| anyhow!("fts: missing primary_id in doc"))
    }

    fn column(&mut self, segment_ord: SegmentOrdinal) -> anyhow::Result<&Column<u64>> {
        let segment = self.searcher.segment_reader(segment_ord);
        if let Some(column) = self.cached.get(&segment.segment_id()) {
            return Ok(column);
        }
        match self.opened.entry(segment_ord) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                self.columns.record_miss(segment.segment_id());
                let column = open_primary_id_column(segment)
                    .map_err(|e| anyhow!("fts: failed to open primary_id column: {e}"))?;
                Ok(entry.insert(column))
            }
        }
    }
}

fn handle_search(
    state: &IndexState,
    table: &RwLock<impl TableSearch>,
    index_key: &IndexKey,
    query_str: &str,
    limit: Limit,
) -> FtsSearchR {
    let body_field = state.schema.get_field("body").unwrap();

    let searcher = state.reader.searcher();
    let query = make_query(&state.index, body_field, query_str)?;
    let limit: usize = (*limit.as_ref()).into();

    let top_docs = searcher
        .search(&query, &TopDocs::with_limit(limit).order_by_score())
        .map_err(|e| anyhow!("fts: search failed: {e}"))?;

    let table = table.read().unwrap();
    let partition_id = find_partition_id(table.deref(), index_key)?;

    let mut primary_ids = HitPrimaryIds::new(&searcher, &state.primary_ids);
    let (primary_keys, scores) = top_docs
        .into_iter()
        .map(|(score, doc_address)| Ok((score, primary_ids.primary_id(doc_address)?)))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|(score, primary_id)| {
            table
                .primary_key(partition_id, primary_id)
                .map(|pk| (pk, score))
        })
        .unzip();

    Ok((primary_keys, scores))
}

const HIGHLIGHT_MAX_NUM_CHARS: usize = 150;
const HIGHLIGHT_PRE_TAG: &str = "<b>";
const HIGHLIGHT_POST_TAG: &str = "</b>";

/// Rebuilds `query`, dropping any `MustNot` clause at every nesting level.
///
/// Works around a Tantivy limitation.
/// `SnippetGenerator` uses `BooleanQuery::query_terms` to determine which terms to highlight.
/// That method walks every subquery regardless of `Occur`, discarding the sign entirely.
/// Without this, a negated term (e.g. `-dog` in `fox -dog`) would still get highlighted
/// in caller-supplied text even though the query excludes documents containing it.
///
/// Returns `Err` for a query construct we cannot see inside since we cannot rule
/// out a `MustNot` clause hidden behind it. The caller surfaces this as a query error
/// rather than silently returning no highlights, since the query may still positively
/// match the document.
fn strip_negated_clauses(query: &dyn Query) -> anyhow::Result<Box<dyn Query>> {
    let Some(boolean_query) = query.downcast_ref::<BooleanQuery>() else {
        if query.downcast_ref::<BoostQuery>().is_some() {
            return Err(QueryError(
                "fts: boosted queries are not supported for highlighting".to_string(),
            )
            .into());
        }
        return Ok(query.box_clone());
    };
    let clauses = boolean_query
        .clauses()
        .iter()
        .filter(|(occur, _)| *occur != Occur::MustNot)
        .map(|(occur, subquery)| Ok((*occur, strip_negated_clauses(subquery.as_ref())?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Box::new(BooleanQuery::new(clauses)))
}

fn handle_highlight(state: &IndexState, query_str: &str, documents: &[String]) -> FtsHighlightR {
    let body_field = state.schema.get_field("body").unwrap();
    let searcher = state.reader.searcher();
    let query = make_query(&state.index, body_field, query_str)?;
    let query = strip_negated_clauses(query.as_ref())?;

    // The generator uses the live index to weight terms by document frequency,
    // prioritizing rarer indexed terms when picking which fragment of a long text to show.
    let mut generator = SnippetGenerator::create(&searcher, query.as_ref(), body_field)
        .map_err(|e| anyhow!("fts: failed to create snippet generator: {e}"))?;
    generator.set_max_num_chars(HIGHLIGHT_MAX_NUM_CHARS);

    Ok(documents
        .iter()
        .map(|text| {
            let mut snippet = generator.snippet(text);
            if snippet.is_empty() {
                return None;
            }
            snippet.set_snippet_prefix_postfix(HIGHLIGHT_PRE_TAG, HIGHLIGHT_POST_TAG);
            Some(snippet.to_html())
        })
        .collect())
}

fn handle_stats(state: &IndexState) -> FtsStatsR {
    let searcher = state.reader.searcher();
    let num_docs = searcher.num_docs();
    let segment_count = searcher.segment_readers().len();
    let size_bytes = searcher
        .space_usage()
        .map_err(|e| anyhow!("fts: failed to compute space usage: {e}"))?
        .total()
        .get_bytes();
    Ok(FtsStats {
        num_docs,
        size_bytes,
        segment_count,
    })
}

fn get_or_create_state<T: TableSearch>(
    states: &mut BTreeMap<IndexId, Arc<IndexState>>,
    table: &RwLock<T>,
    index: &FtsIndexConfiguration,
    tuning: FtsTuning,
) -> Option<Arc<IndexState>> {
    let key = &index.key;
    let index_id = table.read().unwrap().index_id(key)?;
    if let Some(state) = states.get(&index_id) {
        return Some(Arc::clone(state));
    }
    match IndexState::new(index.analyzer, index.positions, tuning) {
        Ok(state) => {
            let state = Arc::new(state);
            states.insert(index_id, Arc::clone(&state));
            Some(state)
        }
        Err(err) => {
            error!("fts: failed to create index state for {key}: {err}");
            None
        }
    }
}

fn get_state<T: TableSearch>(
    states: &BTreeMap<IndexId, Arc<IndexState>>,
    table: &RwLock<T>,
    key: &IndexKey,
) -> Option<Arc<IndexState>> {
    let index_id = table.read().unwrap().index_id(key)?;
    states.get(&index_id).cloned()
}

fn can_allocate_memory(
    rx_allocate: &watch::Receiver<Allocate>,
    allocate_prev: &mut Allocate,
    key: &IndexKey,
) -> bool {
    let allocate = *rx_allocate.borrow();
    if allocate == Allocate::Cannot {
        if *allocate_prev == Allocate::Can {
            error!("Unable to add document for index {key}: not enough memory");
        }
        *allocate_prev = allocate;
        return false;
    }
    *allocate_prev = allocate;
    true
}

pub(crate) fn new(
    index: FtsIndexConfiguration,
    table: Arc<RwLock<impl TableSearch + Send + Sync + 'static>>,
    worker: async_channel::Sender<Worker>,
    memory: mpsc::Sender<Memory>,
    commit_interval: Duration,
    commit_threshold: usize,
    tuning: FtsTuning,
) -> mpsc::Sender<FtsIndex> {
    let (tx, mut rx) = mpsc::channel::<FtsIndex>(perf::channel_size().into());
    tokio::spawn(async move {
        let key = index.key.clone();
        debug!("fts index actor starting for {key}");
        let mut states: BTreeMap<IndexId, Arc<IndexState>> = BTreeMap::new();

        let mut allocate_prev = Allocate::Can;
        let allocate_rx = memory.subscribe_allocate().await;

        let mut interval = tokio::time::interval(commit_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    match msg {
                        FtsIndex::AddDocument {
                            primary_id,
                            document,
                            in_progress,
                        } => {
                            let Some(state) = get_or_create_state(
                                &mut states,
                                table.as_ref(),
                                &index,
                                tuning,
                            ) else {
                                continue;
                            };
                            if !can_allocate_memory(&allocate_rx, &mut allocate_prev, &key) {
                                continue;
                            }
                            let key = key.clone();
                            worker
                                .spawn_blocking(move || {
                                    let pending = handle_add_document(
                                        &state,
                                        primary_id,
                                        document,
                                        in_progress,
                                    );
                                    if pending >= commit_threshold {
                                        commit(&state, &key);
                                    }
                                })
                                .await;
                        }
                        FtsIndex::RemoveDocument {
                            primary_id,
                            in_progress,
                        } => {
                            let Some(state) = get_or_create_state(
                                &mut states,
                                table.as_ref(),
                                &index,
                                tuning,
                            ) else {
                                continue;
                            };
                            let key = key.clone();
                            worker
                                .spawn_blocking(move || {
                                    let pending =
                                        handle_remove_document(&state, primary_id, in_progress);
                                    if pending >= commit_threshold {
                                        commit(&state, &key);
                                    }
                                })
                                .await;
                        }
                        FtsIndex::Count { tx, index_key, .. } => {
                            let result = get_state(&states, table.as_ref(), &index_key)
                                .map(|s| s.reader.searcher().num_docs() as usize)
                                .unwrap_or(0);
                            _ = tx.send(Ok(result));
                        }
                        FtsIndex::Search {
                            index_key,
                            query,
                            limit,
                            tx,
                        } => {
                            let Some(state) = get_state(&states, table.as_ref(), &index_key) else {
                                _ = tx.send(Ok((vec![], vec![])));
                                continue;
                            };
                            let table = Arc::clone(&table);
                            worker
                                .spawn_blocking(move || {
                                    let result = handle_search(
                                        &state,
                                        table.as_ref(),
                                        &index_key,
                                        &query,
                                        limit,
                                    );
                                    _ = tx.send(result);
                                })
                                .await;
                        }
                        FtsIndex::Highlight {
                            index_key,
                            query,
                            documents,
                            tx,
                        } => {
                            let Some(state) = get_state(&states, table.as_ref(), &index_key)
                            else {
                                _ = tx.send(Err(anyhow!("fts: missing index {index_key}")));
                                continue;
                            };
                            worker
                                .spawn_blocking(move || {
                                    let result = handle_highlight(&state, &query, &documents);
                                    _ = tx.send(result);
                                })
                                .await;
                        }
                        FtsIndex::Consolidate { index_key } => {
                            let Some(target) = tuning.target_segments else {
                                continue;
                            };
                            if let Some(state) = get_state(&states, table.as_ref(), &index_key) {
                                start_consolidation(
                                    &state,
                                    index_key,
                                    target,
                                    allocate_rx.clone(),
                                );
                            }
                        }
                        FtsIndex::Stats { index_key, tx } => {
                            let Some(state) = get_state(&states, table.as_ref(), &index_key)
                            else {
                                _ = tx.send(Ok(FtsStats::default()));
                                continue;
                            };
                            worker
                                .spawn_blocking(move || {
                                    let result = handle_stats(&state);
                                    _ = tx.send(result);
                                })
                                .await;
                        }
                    }
                }
                _ = interval.tick() => {
                    for state in states.values() {
                        let state = Arc::clone(state);
                        let key = key.clone();
                        if state.writer.read().unwrap().has_uncommitted_docs() {
                            worker.spawn_blocking(move || commit(&state, &key)).await;
                        } else {
                            worker.spawn_blocking(move || reload_after_merges(&state, &key)).await;
                        }
                    }
                }
            }
        }
        debug!("fts index actor finished for {key}");
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AsyncInProgress;
    use crate::IndexKey;
    use crate::PrimaryKey;
    use crate::table::IndexIdGenerator;
    use crate::table::MockTableSearch;
    use crate::table::PartitionId;
    use crate::worker;
    use rstest::rstest;
    use scylla::value::CqlValue;
    use std::time::Duration;

    use super::super::actor::FtsIndexExt;

    fn make_table_with_keys() -> Arc<RwLock<MockTableSearch>> {
        let index_id = IndexIdGenerator::new().next(true).unwrap();
        let partition_id = PartitionId::global(index_id);
        let mut mock = MockTableSearch::new();
        mock.expect_index_id()
            .returning(move |_index_key| Some(index_id));
        mock.expect_partition_id()
            .returning(move |_index_key, _restrictions| Some((partition_id, None)));
        mock.expect_primary_key()
            .returning(|_partition_id, primary_id| {
                let id_val = u64::from(primary_id);
                Some(PrimaryKey::from(vec![CqlValue::BigInt(id_val as i64)]))
            });
        Arc::new(RwLock::new(mock))
    }

    fn make_index_key() -> IndexKey {
        IndexKey::new(&"ks".into(), &"idx".into())
    }

    fn make_memory_actor() -> mpsc::Sender<Memory> {
        let (tx, mut rx) = mpsc::channel::<Memory>(1);
        tokio::spawn(async move {
            let (watch_tx, _) = watch::channel(Allocate::Can);
            while let Some(msg) = rx.recv().await {
                match msg {
                    Memory::SubscribeAllocate { tx } => {
                        let _ = tx.send(watch_tx.subscribe());
                    }
                }
            }
        });
        tx
    }

    const TEST_COMMIT_INTERVAL: Duration = Duration::from_millis(50);
    const TEST_COMMIT_THRESHOLD: usize = 3;

    fn make_configuration() -> FtsIndexConfiguration {
        FtsIndexConfiguration {
            key: make_index_key(),
            analyzer: Analyzer::default(),
            positions: Positions::default(),
        }
    }

    fn make_sender(table: Arc<RwLock<MockTableSearch>>) -> mpsc::Sender<FtsIndex> {
        make_sender_with_options(table, Analyzer::default(), Positions::default())
    }

    fn make_sender_with_options(
        table: Arc<RwLock<MockTableSearch>>,
        analyzer: Analyzer,
        positions: Positions,
    ) -> mpsc::Sender<FtsIndex> {
        let configuration = FtsIndexConfiguration {
            analyzer,
            positions,
            ..make_configuration()
        };
        make_sender_with_tuning(table, configuration, FtsTuning::default())
    }

    fn make_sender_with_tuning(
        table: Arc<RwLock<MockTableSearch>>,
        configuration: FtsIndexConfiguration,
        tuning: FtsTuning,
    ) -> mpsc::Sender<FtsIndex> {
        new(
            configuration,
            table,
            worker::new(),
            make_memory_actor(),
            TEST_COMMIT_INTERVAL,
            TEST_COMMIT_THRESHOLD,
            tuning,
        )
    }

    async fn add_doc(sender: &mpsc::Sender<FtsIndex>, primary: u64, content: &str) {
        let (tx, mut rx) = mpsc::channel(1);
        sender
            .add_document(
                primary.into(),
                content.into(),
                AsyncInProgress::Fullscan(tx),
            )
            .await
            .unwrap();
        rx.recv().await;
    }

    async fn rm_doc(sender: &mpsc::Sender<FtsIndex>, primary: u64) {
        let (tx, mut rx) = mpsc::channel(1);
        sender
            .remove_document(primary.into(), AsyncInProgress::Fullscan(tx))
            .await
            .unwrap();
        rx.recv().await;
    }

    fn make_memory_actor_cannot_allocate() -> mpsc::Sender<Memory> {
        let (tx, mut rx) = mpsc::channel::<Memory>(1);
        tokio::spawn(async move {
            let (watch_tx, _) = watch::channel(Allocate::Cannot);
            while let Some(msg) = rx.recv().await {
                match msg {
                    Memory::SubscribeAllocate { tx } => {
                        let _ = tx.send(watch_tx.subscribe());
                    }
                }
            }
        });
        tx
    }

    fn tokenize_with(analyzer: Analyzer, text: &str) -> Vec<String> {
        let mut analyzer = build_token_pipeline(analyzer).unwrap();
        let mut stream = analyzer.token_stream(text);
        let mut tokens = Vec::new();
        while stream.advance() {
            tokens.push(stream.token().text.clone());
        }
        tokens
    }

    fn tokenize_with_standard_analyzer(text: &str) -> Vec<String> {
        tokenize_with(Analyzer::Standard, text)
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn add_document_increments_count() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "hello world").await;
        add_doc(&sender, 2, "foo bar").await;

        let key = make_index_key();
        let count = sender.count(key).await.unwrap();

        assert_eq!(count, 2);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn remove_document_decrements_count() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "hello").await;
        add_doc(&sender, 2, "world").await;
        rm_doc(&sender, 2).await;

        let key = make_index_key();
        let count = sender.count(key).await.unwrap();

        assert_eq!(count, 1);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_returns_matching_docs() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "the quick brown fox").await;
        add_doc(&sender, 2, "lazy dog sleeps").await;

        let key = make_index_key();
        let (keys, scores) = sender
            .search(
                key,
                "fox".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(scores.len(), 1);
        assert!(scores.iter().all(|&s| s > 0.0));
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_orders_by_bm25_relevance() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "rust rust rust programming language").await;
        add_doc(&sender, 2, "rust is a systems programming language").await;

        let key = make_index_key();
        let (keys, scores) = sender
            .search(
                key,
                "rust".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(keys.len() >= 2);
        for i in 1..scores.len() {
            assert!(scores[i - 1] >= scores[i], "scores should be descending");
        }
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_returns_empty_for_no_match() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "hello world").await;

        let key = make_index_key();
        let (keys, scores) = sender
            .search(
                key,
                "nonexistentterm".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(keys.is_empty());
        assert!(scores.is_empty());
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn remove_then_search_excludes_removed() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "unique document alpha").await;
        add_doc(&sender, 2, "unique document beta").await;

        rm_doc(&sender, 1).await;

        let key = make_index_key();
        let (keys, scores) = sender
            .search(
                key,
                "unique".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(scores.len(), 1);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn stats_reflects_doc_count_and_segments() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        add_doc(&sender, 1, "hello world").await;
        add_doc(&sender, 2, "foo bar").await;

        let key = make_index_key();
        let stats = sender.stats(key).await.unwrap();

        assert_eq!(stats.num_docs, 2);
        assert!(stats.segment_count > 0);
        assert!(stats.size_bytes > 0);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn stats_for_unknown_index_returns_default() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        let key = make_index_key();
        let stats = sender.stats(key).await.unwrap();

        assert_eq!(stats.num_docs, 0);
        assert_eq!(stats.segment_count, 0);
        assert_eq!(stats.size_bytes, 0);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn add_document_rejected_when_memory_exhausted() {
        let table = make_table_with_keys();
        let memory = make_memory_actor_cannot_allocate();
        let sender = new(
            make_configuration(),
            table,
            worker::new(),
            memory,
            TEST_COMMIT_INTERVAL,
            TEST_COMMIT_THRESHOLD,
            FtsTuning::default(),
        );

        add_doc(&sender, 1, "should not be indexed").await;

        let key = make_index_key();
        let count = sender.count(key).await.unwrap();
        assert_eq!(count, 0);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn threshold_forces_commit_before_interval() {
        let table = make_table_with_keys();
        let memory = make_memory_actor();
        let sender = new(
            make_configuration(),
            table,
            worker::new(),
            memory,
            Duration::from_secs(3600),
            TEST_COMMIT_THRESHOLD,
            FtsTuning::default(),
        );
        let (tx, mut rx) = mpsc::channel(1);

        for primary in 1..=TEST_COMMIT_THRESHOLD as u64 {
            sender
                .add_document(
                    primary.into(),
                    "content".into(),
                    AsyncInProgress::Fullscan(tx.clone()),
                )
                .await
                .unwrap();
        }
        // Each added document holds a Fullscan sender clone in the writer's uncommitted guards.
        // Dropping our own sender leaves only those clones alive, so `recv` returns `None` exactly
        // when the threshold-forced commit clears the guards - i.e. once the commit has completed.
        drop(tx);
        rx.recv().await;
        let count = sender.count(make_index_key()).await.unwrap();

        assert_eq!(count, TEST_COMMIT_THRESHOLD);
    }

    /// Tantivy's default `LogMergePolicy` merges once this many same-level segments exist.
    const MERGE_POLICY_MIN_NUM_SEGMENTS: u64 = 8;
    const MERGE_SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

    async fn add_committed_segment(sender: &mpsc::Sender<FtsIndex>, segment: u64) {
        let (tx, mut rx) = mpsc::channel(1);
        let docs_per_segment = TEST_COMMIT_THRESHOLD as u64;
        for doc in 0..docs_per_segment {
            sender
                .add_document(
                    (segment * docs_per_segment + doc).into(),
                    format!("segment {segment} document {doc} body text"),
                    AsyncInProgress::Fullscan(tx.clone()),
                )
                .await
                .unwrap();
        }
        drop(tx);
        rx.recv().await;
    }

    async fn segment_count(sender: &mpsc::Sender<FtsIndex>) -> usize {
        sender.stats(make_index_key()).await.unwrap().segment_count
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn reader_drops_merged_away_segments_without_further_writes() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        // The last commit leaves exactly enough segments to start a background merge, which
        // finishes after that commit has already reloaded the reader.
        for segment in 0..MERGE_POLICY_MIN_NUM_SEGMENTS {
            add_committed_segment(&sender, segment).await;
        }

        let deadline = tokio::time::Instant::now() + MERGE_SETTLE_TIMEOUT;
        while segment_count(&sender).await as u64 >= MERGE_POLICY_MIN_NUM_SEGMENTS {
            assert!(
                tokio::time::Instant::now() < deadline,
                "reader still serves {} segments after the background merge",
                segment_count(&sender).await
            );
            tokio::time::sleep(TEST_COMMIT_INTERVAL).await;
        }
    }

    fn commit_segments(state: &IndexState, segments: u64) {
        let key = make_index_key();
        for segment in 0..segments {
            let primary_id = PrimaryId::from(segment);
            let (tx, _rx) = mpsc::channel(1);
            handle_add_document(
                state,
                primary_id,
                format!("segment {segment} body text"),
                AsyncInProgress::Fullscan(tx),
            );
            commit(state, &key);
        }
    }

    fn searchable_segment_ids(state: &IndexState) -> BTreeSet<tantivy::index::SegmentId> {
        state
            .index
            .searchable_segment_ids()
            .unwrap()
            .into_iter()
            .collect()
    }

    fn served_segment_ids(state: &IndexState) -> BTreeSet<tantivy::index::SegmentId> {
        state
            .reader
            .searcher()
            .segment_readers()
            .iter()
            .map(|segment| segment.segment_id())
            .collect()
    }

    async fn wait_for_merges(state: &IndexState) {
        let deadline = tokio::time::Instant::now() + MERGE_SETTLE_TIMEOUT;
        while searchable_segment_ids(state).len() as u64 >= MERGE_POLICY_MIN_NUM_SEGMENTS {
            assert!(
                tokio::time::Instant::now() < deadline,
                "background merge did not finish"
            );
            tokio::time::sleep(TEST_COMMIT_INTERVAL).await;
        }
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn reload_after_merges_serves_the_index_searchable_segments() {
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        commit_segments(&state, MERGE_POLICY_MIN_NUM_SEGMENTS);
        wait_for_merges(&state).await;
        assert_ne!(served_segment_ids(&state), searchable_segment_ids(&state));

        reload_after_merges(&state, &make_index_key());

        assert_eq!(served_segment_ids(&state), searchable_segment_ids(&state));
    }

    const SHARED_TERM: &str = "shared";

    fn unique_term(id: u64) -> String {
        format!("doc{id}")
    }

    fn commit_segment_of_docs(state: &IndexState, ids: std::ops::Range<u64>) {
        for id in ids {
            let (tx, _rx) = mpsc::channel(1);
            handle_add_document(
                state,
                PrimaryId::from(id),
                format!("{SHARED_TERM} {}", unique_term(id)),
                AsyncInProgress::Fullscan(tx),
            );
        }
        commit(state, &make_index_key());
    }

    fn search_state(state: &IndexState, query: &str) -> Vec<PrimaryKey> {
        let (keys, _) = handle_search(
            state,
            &make_table_with_keys(),
            &make_index_key(),
            query,
            Limit::from(std::num::NonZeroUsize::new(100).unwrap()),
        )
        .unwrap();
        keys
    }

    fn primary_key(id: u64) -> PrimaryKey {
        PrimaryKey::from(vec![CqlValue::BigInt(id as i64)])
    }

    fn sorted(mut keys: Vec<PrimaryKey>) -> Vec<PrimaryKey> {
        keys.sort();
        keys
    }

    /// Below the merge policy's minimum, so only consolidation can merge them.
    const CONSOLIDATION_TEST_SEGMENTS: u64 = 6;
    const CONSOLIDATION_TEST_TARGET: NonZeroUsize = NonZeroUsize::new(2).unwrap();

    fn tuning_with_target(target_segments: Option<NonZeroUsize>) -> FtsTuning {
        FtsTuning {
            target_segments,
            ..FtsTuning::default()
        }
    }

    async fn sender_with_committed_segments(
        target_segments: Option<NonZeroUsize>,
    ) -> mpsc::Sender<FtsIndex> {
        let sender = make_sender_with_tuning(
            make_table_with_keys(),
            make_configuration(),
            tuning_with_target(target_segments),
        );
        for segment in 0..CONSOLIDATION_TEST_SEGMENTS {
            add_committed_segment(&sender, segment).await;
        }
        sender
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn consolidate_merges_the_index_down_to_the_target_segment_count() {
        let sender = sender_with_committed_segments(Some(CONSOLIDATION_TEST_TARGET)).await;

        sender.consolidate(make_index_key()).await.unwrap();

        let deadline = tokio::time::Instant::now() + MERGE_SETTLE_TIMEOUT;
        while segment_count(&sender).await > CONSOLIDATION_TEST_TARGET.get() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "reader still serves {} segments after consolidation",
                segment_count(&sender).await
            );
            tokio::time::sleep(TEST_COMMIT_INTERVAL).await;
        }
        let docs = CONSOLIDATION_TEST_SEGMENTS as usize * TEST_COMMIT_THRESHOLD;
        assert_eq!(sender.count(make_index_key()).await.unwrap(), docs);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn consolidate_is_ignored_without_a_target() {
        let sender = sender_with_committed_segments(None).await;

        sender.consolidate(make_index_key()).await.unwrap();
        tokio::time::sleep(TEST_COMMIT_INTERVAL * 5).await;

        assert_eq!(
            segment_count(&sender).await as u64,
            CONSOLIDATION_TEST_SEGMENTS
        );
    }

    fn state_with_committed_segments() -> Arc<IndexState> {
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        commit_segments(&state, CONSOLIDATION_TEST_SEGMENTS);
        Arc::new(state)
    }

    fn spawn_consolidation(
        state: &Arc<IndexState>,
        allocate: Allocate,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let (_allocate_tx, allocate_rx) = watch::channel(allocate);
        start_consolidation(
            state,
            make_index_key(),
            CONSOLIDATION_TEST_TARGET,
            allocate_rx,
        )
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_maps_hits_in_every_segment_to_their_primary_keys() {
        const SEGMENTS: u64 = 3;
        const DOCS_PER_SEGMENT: u64 = 4;
        const DOCS: u64 = SEGMENTS * DOCS_PER_SEGMENT;
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        for segment in 0..SEGMENTS {
            commit_segment_of_docs(
                &state,
                segment * DOCS_PER_SEGMENT..(segment + 1) * DOCS_PER_SEGMENT,
            );
        }
        assert!(state.reader.searcher().segment_readers().len() > 1);

        for id in 0..DOCS {
            assert_eq!(
                search_state(&state, &unique_term(id)),
                vec![primary_key(id)]
            );
        }
        assert_eq!(
            sorted(search_state(&state, SHARED_TERM)),
            sorted((0..DOCS).map(primary_key).collect())
        );
    }

    fn cached_segment_ids(state: &IndexState) -> BTreeSet<SegmentId> {
        state.primary_ids.snapshot().keys().cloned().collect()
    }

    fn primary_id_misses(state: &IndexState) -> u64 {
        state.primary_ids.misses.load(Ordering::Relaxed)
    }

    fn all_primary_keys(ids: std::ops::Range<u64>) -> Vec<PrimaryKey> {
        sorted(ids.map(primary_key).collect())
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_reads_primary_ids_from_columns_opened_at_commit() {
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        commit_segment_of_docs(&state, 0..4);
        commit_segment_of_docs(&state, 4..8);
        assert_eq!(cached_segment_ids(&state), served_segment_ids(&state));

        assert_eq!(
            sorted(search_state(&state, SHARED_TERM)),
            all_primary_keys(0..8)
        );
        assert_eq!(primary_id_misses(&state), 0);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn delete_committed_during_consolidation_stays_applied() {
        let state = state_with_committed_segments();
        let consolidation = spawn_consolidation(&state, Allocate::Can).unwrap();

        let (tx, _rx) = mpsc::channel(1);
        handle_remove_document(&state, PrimaryId::from(0), AsyncInProgress::Fullscan(tx));
        commit(&state, &make_index_key());
        consolidation.await.unwrap();

        assert_eq!(
            state.reader.searcher().num_docs(),
            CONSOLIDATION_TEST_SEGMENTS - 1
        );
        assert!(served_segment_ids(&state).len() <= CONSOLIDATION_TEST_TARGET.get());
        assert!(!state.consolidating.load(Ordering::Acquire));
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn reload_after_merges_caches_only_the_served_segments_columns() {
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        commit_segments(&state, MERGE_POLICY_MIN_NUM_SEGMENTS);
        wait_for_merges(&state).await;
        assert_ne!(cached_segment_ids(&state), searchable_segment_ids(&state));

        reload_after_merges(&state, &make_index_key());

        assert_eq!(cached_segment_ids(&state), searchable_segment_ids(&state));
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_opens_a_column_missing_from_the_cache_once_per_query() {
        let state = IndexState::new(
            Analyzer::default(),
            Positions::default(),
            FtsTuning::default(),
        )
        .unwrap();
        commit_segment_of_docs(&state, 0..4);
        *state.primary_ids.served.write().unwrap() = Arc::default();

        assert_eq!(
            sorted(search_state(&state, SHARED_TERM)),
            all_primary_keys(0..4)
        );
        assert_eq!(primary_id_misses(&state), 1);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn consolidation_does_not_merge_when_memory_is_exhausted() {
        let state = state_with_committed_segments();

        spawn_consolidation(&state, Allocate::Cannot)
            .unwrap()
            .await
            .unwrap();

        assert_eq!(
            searchable_segment_ids(&state).len() as u64,
            CONSOLIDATION_TEST_SEGMENTS
        );
        assert!(!state.consolidating.load(Ordering::Acquire));
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn consolidation_already_running_is_not_started_again() {
        let state = state_with_committed_segments();

        let first = spawn_consolidation(&state, Allocate::Can);
        let second = spawn_consolidation(&state, Allocate::Can);

        assert!(first.is_some());
        assert!(second.is_none());
        first.unwrap().await.unwrap();
        assert!(spawn_consolidation(&state, Allocate::Can).is_some());
    }

    #[rstest]
    #[case(15_000_000)]
    #[case(4_293_000_000)]
    #[tokio::test]
    async fn writer_accepts_the_configurable_memory_budget_bounds(#[case] bytes: usize) {
        let tuning = FtsTuning {
            writer_memory_bytes: bytes,
            ..FtsTuning::default()
        };

        let state = IndexState::new(Analyzer::default(), Positions::default(), tuning);

        assert!(state.is_ok(), "{bytes} bytes rejected: {:?}", state.err());
    }

    async fn highlight(
        sender: &mpsc::Sender<FtsIndex>,
        query: &str,
        documents: &[&str],
    ) -> Vec<Option<String>> {
        sender
            .highlight(
                make_index_key(),
                query.into(),
                documents.iter().map(|doc| doc.to_string()).collect(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn highlight_marks_query_terms_in_caller_supplied_text() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "the quick brown fox jumps").await;

        let highlights = highlight(&sender, "fox", &["a completely different fox story"]).await;

        assert_eq!(highlights.len(), 1);
        assert_eq!(
            highlights[0].as_deref(),
            Some("a completely different <b>fox</b> story")
        );
    }

    #[tokio::test]
    async fn highlight_returns_none_when_query_term_was_never_indexed() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "unrelated content about turtles").await;

        let highlights = highlight(&sender, "fox", &["a completely different fox story"]).await;

        assert_eq!(highlights[0], None);
    }

    #[tokio::test]
    async fn highlight_returns_one_entry_per_document_in_order() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 13, "turtles").await;
        add_doc(&sender, 21, "fox").await;
        add_doc(&sender, 34, "dog").await;

        let highlights = highlight(
            &sender,
            "fox OR dog OR turtles",
            &["quick fox jumps", "turtles swim slowly", "lazy dog sleeps"],
        )
        .await;

        assert_eq!(highlights.len(), 3);
        assert_eq!(highlights[0].as_deref(), Some("quick <b>fox</b> jumps"));
        assert_eq!(highlights[1].as_deref(), Some("<b>turtles</b> swim slowly"));
        assert_eq!(highlights[2].as_deref(), Some("lazy <b>dog</b> sleeps"));
    }

    #[tokio::test]
    async fn highlight_returns_none_without_matches() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;

        let highlights = highlight(&sender, "fox", &["turtles all the way down"]).await;

        assert_eq!(highlights[0], None);
    }

    #[tokio::test]
    async fn highlight_returns_none_for_not_matched_or_indexed_documents() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;
        add_doc(&sender, 2, "dog").await;
        // "turtles" is not indexed
        add_doc(&sender, 4, "cat").await;

        let highlights = highlight(
            &sender,
            // "dog" does not appear in the query
            "fox OR turtles OR cat",
            &[
                "quick fox jumps",
                "turtles swim slowly",
                "lazy dog sleeps",
                "cat nap time",
            ],
        )
        .await;

        assert_eq!(highlights.len(), 4);
        assert_eq!(highlights[0].as_deref(), Some("quick <b>fox</b> jumps"));
        assert_eq!(highlights[1], None);
        assert_eq!(highlights[2], None);
        assert_eq!(highlights[3].as_deref(), Some("<b>cat</b> nap time"));
    }

    #[tokio::test]
    async fn highlight_escapes_html_in_fragment_but_not_in_tags() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;

        let highlights =
            highlight(&sender, "fox", &["<script>fox & \"friends\"</script> end"]).await;

        assert_eq!(
            highlights[0].as_deref(),
            Some("&lt;script&gt;<b>fox</b> &amp; &quot;friends&quot;&lt;/script&gt; end")
        );
    }

    #[tokio::test]
    async fn highlight_truncates_to_default_max_num_chars() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "needle").await;

        let padding = "haystack ".repeat(40);
        let text = format!("{padding}needle {padding}");
        let highlights = highlight(&sender, "needle", &[text.as_str()]).await;

        let highlight = highlights[0].as_deref().unwrap();
        let highlight_len = highlight.len();
        assert!(
            highlight_len
                <= HIGHLIGHT_MAX_NUM_CHARS + HIGHLIGHT_PRE_TAG.len() + HIGHLIGHT_POST_TAG.len(),
            "highlight of {highlight_len} chars exceeds the default max_num_chars of {HIGHLIGHT_MAX_NUM_CHARS} plus tag overhead: {highlight}",
        );
        assert!(highlight.contains("<b>needle</b>"));
    }

    #[tokio::test]
    async fn highlight_empty_documents_returns_no_highlights() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;

        assert!(highlight(&sender, "fox", &[]).await.is_empty());
    }

    #[tokio::test]
    async fn highlight_marks_terms_for_phrase_query() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "brown fox").await;

        let highlights = highlight(&sender, "\"brown fox\"", &["the quick brown fox jumps"]).await;

        assert_eq!(
            highlights[0].as_deref(),
            Some("the quick <b>brown</b> <b>fox</b> jumps")
        );
    }

    #[tokio::test]
    async fn highlight_does_not_mark_negated_query_terms() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;
        add_doc(&sender, 2, "dog").await;

        let highlights = highlight(&sender, "fox -dog", &["fox dog"]).await;

        assert_eq!(highlights[0].as_deref(), Some("<b>fox</b> dog"));
    }

    #[tokio::test]
    async fn highlight_marks_positive_terms_in_nested_query_with_negation() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;
        add_doc(&sender, 2, "cat").await;
        add_doc(&sender, 3, "dog").await;

        let highlights = highlight(&sender, "(fox OR cat) -dog", &["fox cat dog"]).await;

        assert_eq!(highlights[0].as_deref(), Some("<b>fox</b> <b>cat</b> dog"));
    }

    #[tokio::test]
    async fn highlight_marks_non_ascii_terms() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "café").await;

        let highlights = highlight(&sender, "café", &["I love a nice café over über coffee"]).await;

        assert_eq!(
            highlights[0].as_deref(),
            Some("I love a nice <b>café</b> over über coffee")
        );
    }

    #[tokio::test]
    async fn highlight_fails_on_unparsable_query() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;

        let result = sender
            .highlight(make_index_key(), "fox AND".into(), vec!["a fox".into()])
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn highlight_fails_for_negated_boosted_query() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;
        add_doc(&sender, 2, "dog").await;

        let result = sender
            .highlight(
                make_index_key(),
                "(fox -dog)^2".into(),
                vec!["fox dog".into()],
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn highlight_fails_for_boosted_query() {
        let table = make_table_with_keys();
        let sender = make_sender(table);
        add_doc(&sender, 1, "fox").await;
        add_doc(&sender, 2, "dog").await;

        // A plain boost carries no negation, but we still cannot see inside it
        // to rule one out, so we report it as unsupported rather than a false "no match".
        let result = sender
            .highlight(make_index_key(), "fox^2".into(), vec!["fox dog".into()])
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn highlight_fails_without_index() {
        let table = make_table_with_keys();
        let sender = make_sender(table);

        let result = sender
            .highlight(make_index_key(), "fox".into(), vec!["a fox".into()])
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn highlight_uses_the_configured_analyzer() {
        let table = make_table_with_keys();
        let sender = make_sender_with_options(table, Analyzer::English, Positions::default());
        add_doc(&sender, 1, "the runners are running").await;

        // The English analyzer stems both the query and the highlighted text,
        // so "run" marks the "running" occurrence in the caller-supplied document.
        let highlights = highlight(&sender, "run", &["a story about running fast"]).await;

        assert_eq!(
            highlights[0].as_deref(),
            Some("a story about <b>running</b> fast")
        );
    }

    #[test]
    fn tokenize_lowercases_mixed_case() {
        assert_eq!(
            tokenize_with_standard_analyzer("Hello WORLD Rust"),
            vec!["hello", "world", "rust"]
        );
    }

    #[test]
    fn tokenize_splits_on_punctuation() {
        assert_eq!(
            tokenize_with_standard_analyzer("hello,world!rust.programming"),
            vec!["hello", "world", "rust", "programming"]
        );
    }

    #[test]
    fn tokenize_removes_english_stop_words() {
        assert_eq!(
            tokenize_with_standard_analyzer("the quick brown fox and a lazy dog"),
            vec!["quick", "brown", "fox", "lazy", "dog"]
        );
    }

    #[test]
    fn tokenize_preserves_unicode_alphanumerics() {
        assert_eq!(
            tokenize_with_standard_analyzer("Café Über Naïve Straße"),
            vec!["café", "über", "naïve", "straße"]
        );
    }

    #[test]
    fn tokenize_empty_string_yields_no_tokens() {
        assert!(tokenize_with_standard_analyzer("").is_empty());
    }

    #[test]
    fn tokenize_whitespace_only_yields_no_tokens() {
        assert!(tokenize_with_standard_analyzer("   \t\n  ").is_empty());
    }

    #[test]
    fn tokenize_punctuation_only_yields_no_tokens() {
        assert!(tokenize_with_standard_analyzer("!@#$ ,.;:").is_empty());
    }

    #[test]
    fn standard_analyzer_does_not_stem() {
        assert_eq!(
            tokenize_with_standard_analyzer("the running runners"),
            vec!["running", "runners"]
        );
    }

    #[rstest]
    #[case(Analyzer::English, "the running runners", vec!["run", "runner"])]
    #[case(Analyzer::German, "die laufenden Läufer", vec!["laufend", "lauf"])]
    #[case(Analyzer::French, "les coureurs courants", vec!["coureur", "cour"])]
    #[case(Analyzer::Spanish, "los corredores corriendo", vec!["corredor", "corr"])]
    #[case(Analyzer::Italian, "i corridori correnti", vec!["corridor", "corrent"])]
    #[case(Analyzer::Portuguese, "os corredores correndo", vec!["corredor", "corr"])]
    #[case(Analyzer::Russian, "и бегущие бегуны", vec!["бегущ", "бегун"])]
    fn language_analyzers_stem_and_remove_stop_words(
        #[case] analyzer: Analyzer,
        #[case] text: &str,
        #[case] expected: Vec<&str>,
    ) {
        assert_eq!(tokenize_with(analyzer, text), expected);
    }

    #[test]
    fn simple_analyzer_lowercases_without_stop_words_or_stemming() {
        assert_eq!(
            tokenize_with(Analyzer::Simple, "The Running Runners, and a dog"),
            vec!["the", "running", "runners", "and", "a", "dog"]
        );
    }

    #[test]
    fn whitespace_analyzer_keeps_case_and_punctuation() {
        assert_eq!(
            tokenize_with(Analyzer::Whitespace, "The Running, Runners!"),
            vec!["The", "Running,", "Runners!"]
        );
    }

    async fn search_phrase(positions: bool) -> FtsSearchR {
        let sender = make_sender_with_options(
            make_table_with_keys(),
            Analyzer::default(),
            Positions::from(positions),
        );

        add_doc(&sender, 1, "quick brown fox").await;
        add_doc(&sender, 2, "brown quick fox").await;

        sender
            .search(
                make_index_key(),
                "\"quick brown\"".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn phrase_query_matches_with_positions() {
        let (keys, _) = search_phrase(true).await.unwrap();

        assert_eq!(keys.len(), 1);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn phrase_query_is_rejected_without_positions() {
        let err = search_phrase(false)
            .await
            .expect_err("phrase query should not be answerable");

        // A QueryError is what makes the endpoint answer 400 rather than 500.
        // The index cannot serve the query, but the service is healthy.
        assert!(
            err.downcast_ref::<QueryError>().is_some(),
            "expected a query error, got: {err}"
        );
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn term_query_works_without_positions() {
        let table = make_table_with_keys();
        let sender = make_sender_with_options(table, Analyzer::default(), Positions::from(false));

        add_doc(&sender, 1, "quick brown fox").await;
        add_doc(&sender, 2, "lazy dog").await;

        let (keys, _) = sender
            .search(
                make_index_key(),
                "fox".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(keys.len(), 1);
    }

    #[rstest]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    async fn search_uses_the_configured_analyzer() {
        let table = make_table_with_keys();
        let sender = make_sender_with_options(table, Analyzer::English, Positions::default());

        add_doc(&sender, 1, "the runners are running").await;

        // Only an analyzer that stems both sides matches "run" against "running".
        let (keys, _) = sender
            .search(
                make_index_key(),
                "run".into(),
                Limit::from(std::num::NonZeroUsize::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(keys.len(), 1);
    }
}
