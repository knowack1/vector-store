/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

//! The query of a search that is one bare word, built without tantivy's query grammar.
//!
//! `QueryParser::parse_query` runs a nom grammar over the query text before it tokenizes
//! the literals it found. For a one-word query the grammar is two thirds of the parse.
//! A query made only of ASCII letters and digits, other than the grammar's operator
//! words, can only parse to one literal of the default field, so it is tokenized the way
//! the parser tokenizes that literal, and turned into the query the parser would build.

use tantivy::Index;
use tantivy::Term;
use tantivy::query::EmptyQuery;
use tantivy::query::Query;
use tantivy::query::TermQuery;
use tantivy::schema::Field;
use tantivy::schema::FieldType;
use tantivy::schema::IndexRecordOption;

/// Words the grammar reads as operators, not as literals.
const OPERATORS: [&str; 4] = ["AND", "OR", "NOT", "IN"];

/// The query `QueryParser::for_index(index, vec![field]).parse_query(query)` builds, or
/// `None` when `query` is not one bare word of an indexed text field, or when the word's
/// tokens make more than one term.
pub(super) fn parse(index: &Index, field: Field, query: &str) -> Option<Box<dyn Query>> {
    if !is_bare_word(query) || !is_indexed_text(index, field) {
        return None;
    }
    let mut terms = tokenize(index, field, query)?;
    match terms.len() {
        0 => Some(Box::new(EmptyQuery)),
        1 => Some(Box::new(TermQuery::new(
            terms.pop()?,
            IndexRecordOption::WithFreqs,
        ))),
        _ => None,
    }
}

fn is_bare_word(query: &str) -> bool {
    !query.is_empty()
        && query.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && !OPERATORS.contains(&query)
}

fn is_indexed_text(index: &Index, field: Field) -> bool {
    match index.schema().get_field_entry(field).field_type() {
        FieldType::Str(options) => options.get_indexing_options().is_some(),
        _ => false,
    }
}

fn tokenize(index: &Index, field: Field, word: &str) -> Option<Vec<Term>> {
    let mut analyzer = index.tokenizer_for_field(field).ok()?;
    let mut terms = Vec::with_capacity(1);
    analyzer.token_stream(word).process(&mut |token| {
        terms.push(Term::from_field_text(field, &token.text));
    });
    Some(terms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Analyzer;
    use crate::Positions;
    use crate::fts_index::tantivy::build_schema;
    use crate::fts_index::tantivy::build_token_pipeline;
    use tantivy::TantivyDocument;
    use tantivy::collector::TopDocs;
    use tantivy::query::QueryParser;
    use tantivy::schema::STRING;
    use tantivy::schema::Schema;
    use tantivy::schema::TextOptions;

    const ANALYZERS: [Analyzer; 10] = [
        Analyzer::Standard,
        Analyzer::English,
        Analyzer::German,
        Analyzer::French,
        Analyzer::Spanish,
        Analyzer::Italian,
        Analyzer::Portuguese,
        Analyzer::Russian,
        Analyzer::Simple,
        Analyzer::Whitespace,
    ];

    /// Bare words: plain, mixed case, stop words of several languages, words the stemmers
    /// change, digits, and operator words in lower case.
    const BARE_WORDS: [&str; 21] = [
        "mocatta",
        "Mocatta",
        "MOCATTA",
        "xjllhsptqcjz",
        "the",
        "The",
        "und",
        "les",
        "running",
        "2024",
        "0",
        "abc123",
        "123abc",
        "and",
        "or",
        "not",
        "in",
        "TO",
        "to",
        "a",
        "I",
    ];

    /// Queries the grammar may read as something other than one literal.
    const NOT_BARE_WORDS: [&str; 27] = [
        "",
        " mocatta",
        "mocatta ",
        "two words",
        "-mocatta",
        "+mocatta",
        "mocatta*",
        "mocatta~1",
        "mocatta^2",
        "body:mocatta",
        "\"mocatta\"",
        "'mocatta'",
        "(mocatta)",
        "[a TO b]",
        "mocatta-pasha",
        "mocatta_pasha",
        "mocatta.pasha",
        "été",
        "naïve",
        "Häuser",
        "AND",
        "OR",
        "NOT",
        "IN",
        "*",
        "mocatta\\",
        "\tmocatta",
    ];

    fn index_with(analyzer: Analyzer) -> (Index, Field) {
        let tokenizer = analyzer.to_string();
        let schema = build_schema(&tokenizer, Positions::default());
        let index = Index::create_in_ram(schema.clone());
        index
            .tokenizers()
            .register(&tokenizer, build_token_pipeline(analyzer).unwrap());
        (index, schema.get_field("body").unwrap())
    }

    fn parser_query(index: &Index, field: Field, query: &str) -> Option<Box<dyn Query>> {
        QueryParser::for_index(index, vec![field])
            .parse_query(query)
            .ok()
    }

    fn describe(query: Option<Box<dyn Query>>) -> Option<String> {
        query.map(|query| format!("{query:?}"))
    }

    #[test]
    fn bare_word_builds_the_query_the_parser_builds() {
        for analyzer in ANALYZERS {
            let (index, field) = index_with(analyzer);
            for word in BARE_WORDS {
                let fast = parse(&index, field, word);
                assert!(
                    fast.is_some(),
                    "{analyzer}: {word:?} not taken as a bare word"
                );
                assert_eq!(
                    describe(fast),
                    describe(parser_query(&index, field, word)),
                    "{analyzer}: {word:?}"
                );
            }
        }
    }

    #[test]
    fn anything_but_a_bare_word_is_left_to_the_parser() {
        for analyzer in ANALYZERS {
            let (index, field) = index_with(analyzer);
            for query in NOT_BARE_WORDS {
                assert!(
                    parse(&index, field, query).is_none(),
                    "{analyzer}: {query:?} taken as a bare word"
                );
            }
        }
    }

    #[test]
    fn random_ascii_words_build_the_query_the_parser_builds() {
        const ALPHABET: &[u8] = b"abcXYZ019ANDORINT";
        let (index, field) = index_with(Analyzer::Standard);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..2000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = 1 + (state % 5) as usize;
            let word: String = (0..len)
                .map(|i| ALPHABET[((state >> (8 * i)) % ALPHABET.len() as u64) as usize] as char)
                .collect();
            let fast = parse(&index, field, &word);
            if fast.is_some() {
                assert_eq!(
                    describe(fast),
                    describe(parser_query(&index, field, &word)),
                    "{word:?}"
                );
            } else {
                assert!(OPERATORS.contains(&word.as_str()), "{word:?} not taken");
            }
        }
    }

    #[test]
    fn bare_word_query_finds_the_documents_the_parser_query_finds() {
        let (index, field) = index_with(Analyzer::English);
        let mut writer = index.writer_with_num_threads(1, 15_000_000).unwrap();
        for body in [
            "Running dogs run far",
            "the dog runs",
            "a runner ran",
            "dogs and cats, running",
            "nothing here",
        ] {
            let mut doc = TantivyDocument::new();
            doc.add_text(field, body);
            writer.add_document(doc).unwrap();
        }
        writer.commit().unwrap();
        let searcher = index.reader().unwrap().searcher();
        let top = |query: Box<dyn Query>| {
            searcher
                .search(query.as_ref(), &TopDocs::with_limit(10).order_by_score())
                .unwrap()
        };
        for word in ["running", "Dogs", "the", "cats", "absent"] {
            let fast = top(parse(&index, field, word).unwrap());
            assert_eq!(
                fast,
                top(parser_query(&index, field, word).unwrap()),
                "{word}"
            );
        }
        assert_eq!(top(parse(&index, field, "running").unwrap()).len(), 3);
    }

    #[test]
    fn fields_other_than_indexed_text_are_left_to_the_parser() {
        let mut schema = Schema::builder();
        let keyword = schema.add_text_field("keyword", STRING);
        let stored = schema.add_text_field("stored", TextOptions::default());
        let number = schema.add_u64_field("number", tantivy::schema::INDEXED);
        let index = Index::create_in_ram(schema.build());
        assert_eq!(
            describe(parse(&index, keyword, "Mocatta")),
            describe(parser_query(&index, keyword, "Mocatta"))
        );
        assert!(parse(&index, keyword, "Mocatta").is_some());
        assert!(parse(&index, stored, "mocatta").is_none());
        assert!(parse(&index, number, "12").is_none());
    }
}
