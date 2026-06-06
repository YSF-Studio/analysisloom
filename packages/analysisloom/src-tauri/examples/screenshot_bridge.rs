//! JSON-line IPC bridge for README screenshots (real Rust forensic commands).
//! Usage: ANALYSISLOOM_FIXTURES_DIR=/path/to/fixtures cargo run --example screenshot_bridge

use analysisloom_lib::commands;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn main() {
    let home = std::env::temp_dir().join(format!("analysisloom_bridge_{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create bridge home");
    // SAFETY: single-threaded bridge process; HOME must point at an isolated DB directory.
    unsafe { std::env::set_var("HOME", &home) };
    analysisloom_lib::db::init().expect("db init");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = serde_json::from_str(&line).unwrap_or_else(|e| {
            json!({ "id": 0, "ok": false, "error": format!("bad json: {e}") })
        });

        if req.get("cmd").is_none() {
            let resp = json!({ "id": req.get("id").cloned().unwrap_or(json!(0)), "ok": false, "error": "missing cmd" });
            writeln!(stdout, "{resp}").unwrap();
            stdout.flush().unwrap();
            continue;
        }

        let id = req.get("id").cloned().unwrap_or(json!(0));
        let cmd = req["cmd"].as_str().unwrap_or("");
        let args = req.get("args").cloned().unwrap_or(json!({}));

        let result = dispatch(&rt, cmd, &args);
        let resp = match result {
            Ok(v) => json!({ "id": id, "ok": true, "result": v }),
            Err(e) => json!({ "id": id, "ok": false, "error": e }),
        };
        writeln!(stdout, "{resp}").unwrap();
        stdout.flush().unwrap();
    }
}

fn arg_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing arg: {key}"))
}

fn arg_opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key).and_then(|v| v.as_i64())
}

fn arg_vec_str(args: &Value, key: &str) -> Result<Vec<String>, String> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| format!("missing arg: {key}"))
}

fn dispatch(rt: &tokio::runtime::Runtime, cmd: &str, args: &Value) -> Result<Value, String> {
    match cmd {
        "demo_fixtures" => {
            let dir = std::env::var("ANALYSISLOOM_FIXTURES_DIR")
                .map_err(|_| "ANALYSISLOOM_FIXTURES_DIR not set".to_string())?;
            let base = std::path::Path::new(&dir);
            Ok(json!({
                "ntfs": base.join("random_ntfs.dd").to_string_lossy(),
                "luks": base.join("luks_volume.dd").to_string_lossy(),
                "carve": base.join("carve_source.dd").to_string_lossy(),
                "sqlite": base.join("messages.db").to_string_lossy(),
                "evidence": base.join("secret_password_log.txt").to_string_lossy(),
                "png": base.join("photo_evidence.png").to_string_lossy(),
            }))
        }
        "list_cases" => Ok(serde_json::to_value(commands::list_cases()?).map_err(|e| e.to_string())?),
        "create_case" => Ok(serde_json::to_value(commands::create_case(
            arg_str(args, "name")?,
            args.get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("Analyst")
                .to_string(),
        )?)
        .map_err(|e| e.to_string())?),
        "get_case" => Ok(serde_json::to_value(commands::get_case(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "delete_case" => {
            commands::delete_case(arg_str(args, "caseId")?)?;
            Ok(Value::Null)
        }
        "parse_mft" => Ok(serde_json::to_value(commands::parse_mft(arg_str(args, "imagePath")?)?)
            .map_err(|e| e.to_string())?),
        "start_carving" => {
            rt.block_on(commands::start_carving(
                arg_str(args, "imagePath")?,
                arg_str(args, "outputDir")?,
            ))?;
            Ok(Value::Null)
        }
        "get_carving_progress" => Ok(serde_json::to_value(commands::get_carving_progress()?)
            .map_err(|e| e.to_string())?),
        "cancel_carving" => {
            commands::cancel_carving();
            Ok(Value::Null)
        }
        "get_carving_result" => Ok(serde_json::to_value(commands::get_carving_result())
            .map_err(|e| e.to_string())?),
        "hash_file" => Ok(serde_json::to_value(commands::hash_file(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "preview_file" => Ok(serde_json::to_value(commands::preview_file(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "sqlite_db_info" => Ok(serde_json::to_value(commands::sqlite_db_info(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "sqlite_table_columns" => Ok(serde_json::to_value(commands::sqlite_table_columns(
            arg_str(args, "path")?,
            arg_str(args, "table")?,
        )?)
        .map_err(|e| e.to_string())?),
        "sqlite_query_table" => Ok(serde_json::to_value(commands::sqlite_query_table(
            arg_str(args, "path")?,
            arg_str(args, "table")?,
            args.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32),
        )?)
        .map_err(|e| e.to_string())?),
        "sqlite_run_query" => Ok(serde_json::to_value(commands::sqlite_run_query(
            arg_str(args, "path")?,
            arg_str(args, "query")?,
            args.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32),
        )?)
        .map_err(|e| e.to_string())?),
        "detect_encrypted" => Ok(serde_json::to_value(commands::detect_encrypted(arg_str(args, "imagePath")?)?)
            .map_err(|e| e.to_string())?),
        "add_evidence" => Ok(json!(commands::add_evidence(
            arg_str(args, "caseId")?,
            arg_str(args, "sourcePath")?,
            arg_str(args, "itemType")?,
            arg_opt_str(args, "sha256"),
            arg_i64(args, "sizeBytes"),
            arg_opt_str(args, "tag"),
            arg_opt_str(args, "note"),
        )?)),
        "list_evidence" => Ok(serde_json::to_value(commands::list_evidence(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "list_findings" => Ok(serde_json::to_value(commands::list_findings(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "case_stats" => Ok(serde_json::to_value(commands::case_stats(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "record_timeline_event" => {
            commands::record_timeline_event(
                arg_str(args, "caseId")?,
                arg_str(args, "timestamp")?,
                arg_str(args, "source")?,
                arg_str(args, "filePath")?,
                arg_str(args, "eventType")?,
            )?;
            Ok(Value::Null)
        }
        "get_timeline" => Ok(serde_json::to_value(commands::get_timeline(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "get_super_timeline" => Ok(serde_json::to_value(commands::get_super_timeline(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "keyword_search" => Ok(serde_json::to_value(commands::keyword_search(
            arg_str(args, "caseId")?,
            arg_str(args, "query")?,
        )?)
        .map_err(|e| e.to_string())?),
        "unified_search" => Ok(serde_json::to_value(commands::unified_search(
            arg_str(args, "caseId")?,
            arg_str(args, "query")?,
        )?)
        .map_err(|e| e.to_string())?),
        "hex_search" => Ok(serde_json::to_value(commands::hex_search(
            arg_str(args, "caseId")?,
            arg_str(args, "hexPattern")?,
        )?)
        .map_err(|e| e.to_string())?),
        "add_bookmark" => Ok(json!(commands::add_bookmark(
            arg_str(args, "caseId")?,
            arg_str(args, "filePath")?,
            args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as i64,
            arg_opt_str(args, "tag"),
            arg_opt_str(args, "note"),
        )?)),
        "list_bookmarks" => Ok(serde_json::to_value(commands::list_bookmarks(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "delete_bookmark" => {
            commands::delete_bookmark(args.get("id").and_then(|v| v.as_i64()).unwrap_or(0))?;
            Ok(Value::Null)
        }
        "log_action" => {
            commands::log_action(
                arg_str(args, "caseId")?,
                arg_str(args, "action")?,
                arg_str(args, "detail")?,
            )?;
            Ok(Value::Null)
        }
        "get_audit_log" => Ok(serde_json::to_value(commands::get_audit_log(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        "generate_case_report" => Ok(json!(commands::generate_case_report(
            arg_str(args, "caseId")?,
            arg_str(args, "format")?,
        )?)),
        "analyze_registry_hive" => Ok(serde_json::to_value(commands::analyze_registry_hive(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "scan_registry_directory" => Ok(serde_json::to_value(commands::scan_registry_directory(arg_str(args, "dir")?)?)
            .map_err(|e| e.to_string())?),
        "yara_scan_paths" => Ok(serde_json::to_value(commands::yara_scan_paths(
            arg_vec_str(args, "paths")?,
            arg_opt_str(args, "rulesPath"),
        )?)
        .map_err(|e| e.to_string())?),
        "yara_builtin_rule_count" => Ok(json!(commands::yara_builtin_rule_count()?)),
        "analyze_antiforensics_mft" => Ok(serde_json::to_value(commands::analyze_antiforensics_mft(
            arg_str(args, "imagePath")?,
        )?)
        .map_err(|e| e.to_string())?),
        "analyze_antiforensics_files" => Ok(serde_json::to_value(commands::analyze_antiforensics_files(
            arg_vec_str(args, "paths")?,
        )?)
        .map_err(|e| e.to_string())?),
        "scan_browser_artifacts" => Ok(serde_json::to_value(commands::scan_browser_artifacts(arg_str(args, "root")?)?)
            .map_err(|e| e.to_string())?),
        "analyze_browser_db" => Ok(serde_json::to_value(commands::analyze_browser_db(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "nsrl_lookup_file" => Ok(serde_json::to_value(commands::nsrl_lookup_file(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "nsrl_lookup_hash" => Ok(serde_json::to_value(commands::nsrl_lookup_hash(arg_str(args, "sha256")?)?)
            .map_err(|e| e.to_string())?),
        "nsrl_import" => Ok(json!(commands::nsrl_import(arg_str(args, "path")?)?)),
        "nsrl_seed_builtin" => Ok(json!(commands::nsrl_seed_builtin()?)),
        "nsrl_stats" => Ok(commands::nsrl_stats()?),
        "parse_volatility_json" => Ok(serde_json::to_value(commands::parse_volatility_json(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "about_info" => Ok(commands::about_info()),
        "parse_evtx_log" => Ok(serde_json::to_value(commands::parse_evtx_log(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "scan_evtx_directory" => Ok(serde_json::to_value(commands::scan_evtx_directory(arg_str(args, "dir")?)?)
            .map_err(|e| e.to_string())?),
        "scan_macos_artifacts" => Ok(serde_json::to_value(commands::scan_macos_artifacts(arg_str(args, "root")?)?)
            .map_err(|e| e.to_string())?),
        "analyze_macos_plist" => Ok(serde_json::to_value(commands::analyze_macos_plist(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "analyze_pcap" => Ok(serde_json::to_value(commands::analyze_pcap(arg_str(args, "path")?)?)
            .map_err(|e| e.to_string())?),
        "export_case_bundle" => Ok(serde_json::to_value(commands::export_case_bundle(
            arg_str(args, "caseId")?,
            arg_str(args, "outputPath")?,
        )?)
        .map_err(|e| e.to_string())?),
        "import_hash_manifest" => Ok(serde_json::to_value(commands::import_hash_manifest(
            arg_str(args, "caseId")?,
            arg_str(args, "path")?,
        )?)
        .map_err(|e| e.to_string())?),
        "get_case_manifest" => Ok(commands::get_case_manifest(arg_str(args, "caseId")?)?),
        "verify_evidence_integrity" => Ok(serde_json::to_value(commands::verify_evidence_integrity(
            arg_str(args, "caseId")?,
            arg_str(args, "filePath")?,
            arg_str(args, "computedSha256")?,
        )?)
        .map_err(|e| e.to_string())?),
        "append_case_note" => Ok(json!(commands::append_case_note(
            arg_str(args, "caseId")?,
            arg_str(args, "body")?,
            arg_opt_str(args, "filePath"),
        )?)),
        "list_case_notes" => Ok(serde_json::to_value(commands::list_case_notes(arg_str(args, "caseId")?)?)
            .map_err(|e| e.to_string())?),
        _ => Err(format!("unknown command: {cmd}")),
    }
}
