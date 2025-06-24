/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use std::fs;
use std::io::Write;
use vector_store::httproutes::api;

fn main() -> anyhow::Result<()> {
    let openapi = api();
    let json = serde_json::to_string_pretty(&openapi)?;

    let mut file = fs::File::create("openapi.json")?;
    file.write_all(json.as_bytes())?;

    println!("OpenAPI specification written to openapi.json");
    Ok(())
}
