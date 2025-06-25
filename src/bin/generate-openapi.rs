use std::env;
use std::fs;
use std::io::Write;
use vector_store::httproutes::api;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let pathname = if args.len() > 1 {
        &args[1]
    } else {
        "openapi.json"
    };

    let openapi = api();
    let json = serde_json::to_string_pretty(&openapi)?;

    let mut file = fs::File::create(pathname)?;
    file.write_all(json.as_bytes())?;

    println!("OpenAPI specification written to {}", pathname);
    Ok(())
}
