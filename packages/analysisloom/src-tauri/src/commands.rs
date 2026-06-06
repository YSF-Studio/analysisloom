use crate::forensic::{
    self, acquisition, antiforensics, browser, bundle, carving, case_guard, chat, email,
    encryption, evidence, evtx, hashing, integrity, linux, macos, memory, nsrl, ntfs, pcap,
    plugins, preview, registry, report, report_meta, sqlite, steganography, timeline,
    windows_artifacts, yara, ProgressState,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../../src/lib/generated/")]
pub struct Case {
    pub id: String,
    pub name: String,
    pub operator: Option<String>,
    pub created_at: String,
    pub status: String,
    #[serde(default)]
    pub sealed_at: Option<String>,
    #[serde(default)]
    pub sealed_by: Option<String>,
    #[serde(default)]
    pub seal_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub file_path: String,
    pub offset: u64,
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../../src/lib/generated/")]
pub struct EvidenceItem {
    pub id: String,
    pub case_id: String,
    pub source_path: String,
    pub item_type: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
    pub acquired_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: i64,
    pub description: String,
    pub file_path: String,
    pub severity: String,
    pub created_at: Option<String>,
    #[serde(default)]
    pub review_status: Option<String>,
    #[serde(default)]
    pub reviewer: Option<String>,
    #[serde(default)]
    pub reviewed_at: Option<String>,
    #[serde(default)]
    pub review_note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../../src/lib/generated/")]
pub struct CaseStats {
    pub evidence_count: i64,
    pub findings_count: i64,
    pub bookmark_count: i64,
    pub timeline_count: i64,
}

// ─── Case Management ───

#[tauri::command]
pub fn list_cases() -> Result<Vec<Case>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare(
            "SELECT id, name, operator, created_at, status, sealed_at, sealed_by, seal_hash FROM cases ORDER BY created_at DESC",
        )
        .map_err(|e| e.to_string())?;
    let cases = stmt
        .query_map([], |row| {
            Ok(Case {
                id: row.get(0)?,
                name: row.get(1)?,
                operator: row.get(2)?,
                created_at: row.get(3)?,
                status: row.get(4)?,
                sealed_at: row.get(5)?,
                sealed_by: row.get(6)?,
                seal_hash: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(cases)
}

#[tauri::command]
pub fn create_case(name: String, operator: String) -> Result<Case, String> {
    let db = crate::db::conn();
    let id = evidence::EvidenceId::new("ANL").to_string();
    db.execute(
        "INSERT INTO cases (id, name, operator) VALUES (?1, ?2, ?3)",
        rusqlite::params![id, name, operator],
    )
    .map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    Ok(Case {
        id,
        name,
        operator: Some(operator),
        created_at: now,
        status: "active".into(),
        sealed_at: None,
        sealed_by: None,
        seal_hash: None,
    })
}

#[tauri::command]
pub fn get_case(id: String) -> Result<Case, String> {
    let db = crate::db::conn();
    db.query_row(
        "SELECT id, name, operator, created_at, status, sealed_at, sealed_by, seal_hash FROM cases WHERE id = ?1",
        [&id],
        |row| {
            Ok(Case {
                id: row.get(0)?,
                name: row.get(1)?,
                operator: row.get(2)?,
                created_at: row.get(3)?,
                status: row.get(4)?,
                sealed_at: row.get(5)?,
                sealed_by: row.get(6)?,
                seal_hash: row.get(7)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn seal_case(case_id: String, operator: String) -> Result<Case, String> {
    case_guard::ensure_case_mutable(&case_id)?;
    let seal_hash = compute_case_seal_hash(&case_id)?;

    {
        let db = crate::db::conn();
        db.execute(
            "UPDATE cases SET status = 'sealed', sealed_at = datetime('now'), sealed_by = ?2, seal_hash = ?3 WHERE id = ?1",
            rusqlite::params![case_id, operator, seal_hash],
        )
        .map_err(|e| e.to_string())?;
    }

    let _ = log_action(
        case_id.clone(),
        "SEAL_CASE".into(),
        format!("Case sealed by {operator} — digest {seal_hash}"),
    );

    get_case(case_id)
}

fn compute_case_seal_hash(case_id: &str) -> Result<String, String> {
    let db = crate::db::conn();
    let mut parts = vec![];

    let mut estmt = db
        .prepare("SELECT sha256 FROM evidence_items WHERE case_id = ?1 ORDER BY source_path")
        .map_err(|e| e.to_string())?;
    for h in estmt
        .query_map([case_id], |row| row.get::<_, Option<String>>(0))
        .map_err(|e| e.to_string())?
        .flatten()
        .flatten()
    {
        parts.push(h);
    }

    let mut fstmt = db
        .prepare("SELECT id, description, file_path, severity, review_status FROM findings WHERE case_id = ?1 ORDER BY id")
        .map_err(|e| e.to_string())?;
    for row in fstmt
        .query_map([case_id], |row| {
            Ok(format!(
                "{}|{}|{}|{}|{}",
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?
                    .unwrap_or_else(|| "pending".into()),
            ))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
    {
        parts.push(row);
    }

    let last_audit: String = db
        .query_row(
            "SELECT entry_hash FROM audit_log WHERE case_id = ?1 ORDER BY id DESC LIMIT 1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or_default();
    parts.push(last_audit);

    Ok(hashing::multi_hash_buffer(parts.join("\n").as_bytes())
        .sha256
        .unwrap_or_default())
}

#[tauri::command]
pub fn delete_case(id: String) -> Result<(), String> {
    let db = crate::db::conn();
    let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
    for table in [
        "evidence_items",
        "timeline_events",
        "findings",
        "audit_log",
        "bookmarks",
        "case_manifest",
        "case_notes",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE case_id = ?1"), [&id])
            .map_err(|e| e.to_string())?;
    }
    tx.execute("DELETE FROM cases WHERE id = ?1", [&id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

// ─── NTFS Browser ───

#[tauri::command]
pub fn parse_mft(image_path: String) -> Result<Vec<ntfs::MftEntry>, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    ntfs::parse_mft(&image_path, &cancel)
}

// ─── File Carving ───

#[tauri::command]
pub async fn start_carving(image_path: String, output_dir: String) -> Result<(), String> {
    forensic::CANCEL_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
    *forensic::PROGRESS_STATE.lock().unwrap() = ProgressState::default();
    let cancel = forensic::CANCEL_FLAG.clone();

    tokio::task::spawn_blocking(move || {
        let _ = carving::carve_files(&image_path, &output_dir, &cancel);
    });

    Ok(())
}

#[tauri::command]
pub fn get_carving_progress() -> Result<ProgressState, String> {
    forensic::PROGRESS_STATE
        .lock()
        .map(|s| s.clone())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn cancel_carving() {
    forensic::CANCEL_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[tauri::command]
pub fn get_carving_result() -> Option<carving::CarvingResult> {
    forensic::CARVING_RESULT.lock().ok()?.clone()
}

// ─── Evidence & Findings ───

#[tauri::command]
pub fn add_evidence(
    case_id: String,
    source_path: String,
    item_type: String,
    sha256: Option<String>,
    size_bytes: Option<i64>,
    tag: Option<String>,
    note: Option<String>,
) -> Result<String, String> {
    case_guard::ensure_case_mutable(&case_id)?;
    let db = crate::db::conn();
    let id = evidence::EvidenceId::new("EVD").to_string();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

    db.execute(
        "INSERT INTO evidence_items (id, case_id, source_path, type, sha256, size_bytes, acquired_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, case_id, source_path, item_type, sha256, size_bytes, now],
    )
    .map_err(|e| e.to_string())?;

    let description = note
        .clone()
        .unwrap_or_else(|| format!("Evidence: {source_path}"));
    let severity = if tag.as_deref() == Some("critical") {
        "critical"
    } else if tag.as_deref() == Some("high") {
        "high"
    } else {
        "info"
    };

    db.execute(
        "INSERT INTO findings (case_id, description, file_path, severity) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![case_id, description, source_path, severity],
    )
    .map_err(|e| e.to_string())?;

    if note.is_some() || tag.is_some() {
        db.execute(
            "INSERT INTO bookmarks (case_id, file_path, tag, note) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![case_id, source_path, tag, note.unwrap_or_default()],
        )
        .map_err(|e| e.to_string())?;
    }

    db.execute(
        "INSERT INTO audit_log (case_id, action, detail) VALUES (?1, 'ADD_EVIDENCE', ?2)",
        rusqlite::params![case_id, format!("{id} — {source_path}")],
    )
    .map_err(|e| e.to_string())?;

    Ok(id)
}

#[tauri::command]
pub fn list_evidence(case_id: String) -> Result<Vec<EvidenceItem>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare(
            "SELECT id, case_id, source_path, type, sha256, size_bytes, acquired_at FROM evidence_items WHERE case_id = ?1 ORDER BY acquired_at DESC",
        )
        .map_err(|e| e.to_string())?;
    let items = stmt
        .query_map([case_id], |row| {
            Ok(EvidenceItem {
                id: row.get(0)?,
                case_id: row.get(1)?,
                source_path: row.get(2)?,
                item_type: row.get(3)?,
                sha256: row.get(4)?,
                size_bytes: row.get(5)?,
                acquired_at: row.get(6)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(items)
}

#[tauri::command]
pub fn list_findings(case_id: String) -> Result<Vec<Finding>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare(
            "SELECT id, description, file_path, severity, created_at, review_status, reviewer, reviewed_at, review_note FROM findings WHERE case_id = ?1 ORDER BY id DESC",
        )
        .map_err(|e| e.to_string())?;
    let items = stmt
        .query_map([case_id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                description: row.get(1)?,
                file_path: row.get(2)?,
                severity: row.get(3)?,
                created_at: row.get(4)?,
                review_status: row.get(5)?,
                reviewer: row.get(6)?,
                reviewed_at: row.get(7)?,
                review_note: row.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(items)
}

#[tauri::command]
pub fn case_stats(case_id: String) -> Result<CaseStats, String> {
    let db = crate::db::conn();
    let count = |sql: &str| -> i64 { db.query_row(sql, [&case_id], |row| row.get(0)).unwrap_or(0) };
    Ok(CaseStats {
        evidence_count: count("SELECT COUNT(*) FROM evidence_items WHERE case_id = ?1"),
        findings_count: count("SELECT COUNT(*) FROM findings WHERE case_id = ?1"),
        bookmark_count: count("SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1"),
        timeline_count: count("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?1"),
    })
}

// ─── Timeline ───

#[tauri::command]
pub fn record_timeline_event(
    case_id: String,
    timestamp: String,
    source: String,
    file_path: String,
    event_type: String,
) -> Result<(), String> {
    case_guard::ensure_case_mutable(&case_id)?;
    crate::db::conn()
        .execute(
            "INSERT INTO timeline_events (case_id, timestamp, source, file_path, event_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![case_id, timestamp, source, file_path, event_type],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_timeline(case_id: String) -> Result<Vec<serde_json::Value>, String> {
    let db = crate::db::conn();
    let mut stmt = db.prepare(
        "SELECT timestamp, source, file_path, event_type FROM timeline_events WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 200"
    ).map_err(|e| e.to_string())?;
    let events = stmt
        .query_map([case_id], |row| {
            Ok(serde_json::json!({
                "timestamp": row.get::<_, String>(0)?,
                "source": row.get::<_, String>(1)?,
                "filePath": row.get::<_, String>(2)?,
                "eventType": row.get::<_, String>(3)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(events)
}

// ─── Keyword Search ───

#[tauri::command]
pub fn keyword_search(case_id: String, query: String) -> Result<Vec<SearchResult>, String> {
    unified_search(case_id, query)
}

#[tauri::command]
pub fn unified_search(case_id: String, query: String) -> Result<Vec<SearchResult>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare("SELECT source_path FROM evidence_items WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
    let paths: Vec<String> = stmt
        .query_map([&case_id], |row| row.get(0))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    if forensic::search::is_hex_query(&query) {
        let hex_q = forensic::search::normalize_hex_query(&query);
        let hits = forensic::search::hex_search_paths(&paths, &hex_q)?;
        return Ok(hits
            .into_iter()
            .map(|h| SearchResult {
                file_path: h.file_path,
                offset: h.offset,
                context: h.context,
            })
            .collect());
    }

    let regex = regex::Regex::new(&format!("(?i){}", regex::escape(&query)))
        .map_err(|e| format!("Invalid regex: {e}"))?;

    let mut results = vec![];
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for (line_no, line) in content.lines().enumerate() {
                if regex.is_match(line) {
                    results.push(SearchResult {
                        file_path: path.clone(),
                        offset: line_no as u64,
                        context: line.to_string(),
                    });
                }
            }
        }
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(text) = std::str::from_utf8(&data) {
                if regex.is_match(text) && results.iter().all(|r| r.file_path != path) {
                    results.push(SearchResult {
                        file_path: path.clone(),
                        offset: 0,
                        context: text.chars().take(120).collect(),
                    });
                }
            }
        }
    }
    Ok(results)
}

#[tauri::command]
pub fn hex_search(case_id: String, hex_pattern: String) -> Result<Vec<SearchResult>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare("SELECT source_path FROM evidence_items WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
    let paths: Vec<String> = stmt
        .query_map([&case_id], |row| row.get(0))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    let hits = forensic::search::hex_search_paths(&paths, &hex_pattern)?;
    Ok(hits
        .into_iter()
        .map(|h| SearchResult {
            file_path: h.file_path,
            offset: h.offset,
            context: h.context,
        })
        .collect())
}

// ─── File Preview & Hashing ───

#[tauri::command]
pub fn preview_file(path: String) -> Result<preview::PreviewResult, String> {
    preview::preview_file(&path)
}

#[tauri::command]
pub fn hash_file(path: String) -> Result<hashing::HashSet, String> {
    hashing::multi_hash_file(&path)
}

// ─── SQLite Artifact Browser ───

#[tauri::command]
pub fn sqlite_db_info(path: String) -> Result<sqlite::SqliteDbInfo, String> {
    sqlite::db_info(&path)
}

#[tauri::command]
pub fn sqlite_table_columns(
    path: String,
    table: String,
) -> Result<Vec<sqlite::SqliteColumn>, String> {
    sqlite::table_columns(&path, &table)
}

#[tauri::command]
pub fn sqlite_query_table(
    path: String,
    table: String,
    limit: Option<u32>,
) -> Result<sqlite::SqliteQueryResult, String> {
    sqlite::query_table(&path, &table, limit.unwrap_or(100))
}

#[tauri::command]
pub fn sqlite_run_query(
    path: String,
    query: String,
    limit: Option<u32>,
) -> Result<sqlite::SqliteQueryResult, String> {
    sqlite::run_select(&path, &query, limit.unwrap_or(100))
}

// ─── Encryption Detection ───

#[tauri::command]
pub fn detect_encrypted(image_path: String) -> Result<Vec<encryption::EncryptedFinding>, String> {
    encryption::detect_encrypted(&image_path)
}

// ─── Report Generation ───

#[tauri::command]
pub fn generate_case_report(case_id: String, format: String) -> Result<String, String> {
    let (case, timeline, evidence, findings, audit, evidence_paths) = {
        let db = crate::db::conn();

        // Get case info
        let case: Case = db
        .query_row(
            "SELECT id, name, operator, created_at, status, sealed_at, sealed_by, seal_hash FROM cases WHERE id = ?1",
            [&case_id],
            |row| {
                Ok(Case {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    operator: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
                    sealed_at: row.get(5)?,
                    sealed_by: row.get(6)?,
                    seal_hash: row.get(7)?,
                })
            },
        )
        .map_err(|e| format!("Case not found: {e}"))?;

        // Get timeline events
        let mut stmt = db.prepare(
        "SELECT timestamp, source, file_path, event_type FROM timeline_events WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 100"
    ).map_err(|e| e.to_string())?;
        let timeline: Vec<String> = stmt
            .query_map([&case_id], |row| {
                Ok(format!(
                    "{} | {} | {} ({})",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(1)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        // Get evidence items
        let mut stmt = db
        .prepare(
            "SELECT source_path, type, sha256, size_bytes FROM evidence_items WHERE case_id = ?1",
        )
        .map_err(|e| e.to_string())?;
        let evidence: Vec<String> = stmt
            .query_map([&case_id], |row| {
                Ok(format!(
                    "{} ({}) — {} bytes — SHA256: {}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, String>(2).unwrap_or_default(),
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        // Get findings
        let mut stmt = db
        .prepare("SELECT description, file_path, severity, review_status FROM findings WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
        let findings: Vec<String> = stmt
            .query_map([&case_id], |row| {
                Ok(format!(
                    "[{}] {} — {} (review: {})",
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(3)?
                        .unwrap_or_else(|| "pending".into()),
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        // Get audit trail
        let mut stmt = db.prepare(
        "SELECT timestamp, action, detail FROM audit_log WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 50"
    ).map_err(|e| e.to_string())?;
        let audit: Vec<String> = stmt
            .query_map([&case_id], |row| {
                Ok(format!(
                    "{} | {} — {}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        let mut estmt = db
            .prepare("SELECT source_path, sha256 FROM evidence_items WHERE case_id = ?1")
            .map_err(|e| e.to_string())?;
        let evidence_paths: Vec<(String, Option<String>)> = estmt
            .query_map([&case_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        (case, timeline, evidence, findings, audit, evidence_paths)
    };

    let manifest = load_case_manifest(&case_id);
    let hash_chain = integrity::build_hash_chain_report(manifest.as_ref(), &evidence_paths);
    let analyst_notes = list_case_notes_inner(&case_id)?;
    let visuals = collect_report_visuals(&case_id)?;

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let operator_name = case.operator.clone().unwrap_or_default();

    if format == "html" {
        let html = generate_html_report(
            &case,
            &timeline,
            &evidence,
            &findings,
            &audit,
            &now,
            &hash_chain,
            &analyst_notes,
            &visuals,
        );
        let dir = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let out_path = format!(
            "{}/analysisloom_report_{}.html",
            dir,
            &case_id[..8.min(case_id.len())]
        );
        std::fs::write(&out_path, &html).map_err(|e| format!("Write error: {e}"))?;
        Ok(out_path)
    } else {
        // Generate PDF
        let sections = vec![
            report::ReportSection {
                heading: "Case Information".into(),
                content: format!(
                    "Case: {}\nOperator: {}\nStatus: {}\nCreated: {}",
                    case.name, operator_name, case.status, case.created_at
                ),
            },
            report::ReportSection {
                heading: "Timeline Events".into(),
                content: if timeline.is_empty() {
                    "No timeline events recorded.".into()
                } else {
                    timeline.join("\n")
                },
            },
            report::ReportSection {
                heading: "Evidence Items".into(),
                content: if evidence.is_empty() {
                    "No evidence items recorded.".into()
                } else {
                    evidence.join("\n")
                },
            },
            report::ReportSection {
                heading: "Findings".into(),
                content: if findings.is_empty() {
                    "No findings recorded.".into()
                } else {
                    findings.join("\n")
                },
            },
            report::ReportSection {
                heading: "Audit Trail".into(),
                content: if audit.is_empty() {
                    "No audit log entries.".into()
                } else {
                    audit.join("\n")
                },
            },
            report::ReportSection {
                heading: "Tool Limitations (ISO 27042 §10.1)".into(),
                content: report_meta::limitations_text(),
            },
            report::ReportSection {
                heading: "Hash Chain Validation (NIST SP 800-86 §3.4.1)".into(),
                content: integrity::hash_chain_text(&hash_chain),
            },
            report::ReportSection {
                heading: "Analyst Notes (SWGDE §4.4)".into(),
                content: if analyst_notes.is_empty() {
                    "No analyst notes recorded during examination.".into()
                } else {
                    analyst_notes
                        .iter()
                        .map(|n| {
                            let fp = n
                                .get("filePath")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                                .map(|s| format!(" [{s}]"))
                                .unwrap_or_default();
                            format!(
                                "{} — {}{}",
                                n["timestamp"].as_str().unwrap_or("—"),
                                n["body"].as_str().unwrap_or(""),
                                fp
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            },
            report::ReportSection {
                heading: "Finding Visual Documentation".into(),
                content: if visuals.is_empty() {
                    "No visual captures for bookmarks or critical findings.".into()
                } else {
                    visuals
                        .iter()
                        .map(|v| format!("{} — {} ({})", v.title, v.file_path, v.visual_type))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            },
        ];

        let pdf = report::generate_pdf_report(&report::PdfReport {
            title: format!("Forensic Analysis Report — {}", case.name),
            evidence_id: case_id.clone(),
            operator: operator_name.clone(),
            case_name: case.name,
            device: "AnalysisLoom Workstation".into(),
            date: now,
            sections,
        })?;

        let dir = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let out_path = format!(
            "{}/analysisloom_report_{}.pdf",
            dir,
            &case_id[..8.min(case_id.len())]
        );
        std::fs::write(&out_path, &pdf).map_err(|e| format!("Write error: {e}"))?;
        Ok(out_path)
    }
}

struct ReportVisual {
    title: String,
    file_path: String,
    visual_type: String,
    content: String,
}

fn is_image_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    ["png", "jpg", "jpeg", "gif", "webp", "bmp"]
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

fn collect_report_visuals(case_id: &str) -> Result<Vec<ReportVisual>, String> {
    let db = crate::db::conn();
    let mut paths: Vec<(String, String)> = vec![];

    let mut stmt = db
        .prepare(
            "SELECT file_path, COALESCE(note, tag, 'Bookmark') FROM bookmarks WHERE case_id = ?1",
        )
        .map_err(|e| e.to_string())?;
    for row in stmt
        .query_map([case_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
    {
        paths.push(row);
    }

    let mut stmt = db
        .prepare(
            "SELECT file_path, description FROM findings WHERE case_id = ?1 AND severity IN ('critical', 'high')",
        )
        .map_err(|e| e.to_string())?;
    for row in stmt
        .query_map([case_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
    {
        if !paths.iter().any(|(p, _)| p == &row.0) {
            paths.push(row);
        }
    }

    let mut visuals = vec![];
    for (file_path, title) in paths {
        if is_image_path(&file_path) {
            if let Ok(preview) = preview::preview_file(&file_path) {
                if let preview::PreviewContent::Image { data_base64, .. } = preview.preview {
                    visuals.push(ReportVisual {
                        title,
                        file_path: file_path.clone(),
                        visual_type: "image".into(),
                        content: data_base64,
                    });
                    continue;
                }
            }
        }
        if let Ok(preview) = preview::preview_file(&file_path) {
            if let preview::PreviewContent::Text(text) = preview.preview {
                let excerpt: String = text.chars().take(800).collect();
                visuals.push(ReportVisual {
                    title,
                    file_path,
                    visual_type: "text".into(),
                    content: excerpt,
                });
            }
        }
    }
    Ok(visuals)
}

fn load_case_manifest(case_id: &str) -> Option<integrity::HashManifest> {
    let db = crate::db::conn();
    let json: String = db
        .query_row(
            "SELECT manifest_json FROM case_manifest WHERE case_id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .ok()?;
    serde_json::from_str(&json).ok()
}

fn list_case_notes_inner(case_id: &str) -> Result<Vec<serde_json::Value>, String> {
    let db = crate::db::conn();
    let mut stmt = db
        .prepare(
            "SELECT timestamp, body, file_path FROM case_notes WHERE case_id = ?1 ORDER BY timestamp ASC",
        )
        .map_err(|e| e.to_string())?;
    let notes = stmt
        .query_map([case_id], |row| {
            Ok(serde_json::json!({
                "timestamp": row.get::<_, String>(0)?,
                "body": row.get::<_, String>(1)?,
                "filePath": row.get::<_, Option<String>>(2)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(notes)
}

fn visuals_html(visuals: &[ReportVisual]) -> String {
    if visuals.is_empty() {
        return "<p><em>No visual captures for bookmarks or critical findings</em></p>".into();
    }
    visuals
        .iter()
        .map(|v| {
            if v.visual_type == "image" {
                format!(
                    "<div class=\"visual\"><h4>{}</h4><p class=\"mono\">{}</p><img src=\"data:image/png;base64,{}\" alt=\"{}\"/></div>",
                    html_escape(&v.title),
                    html_escape(&v.file_path),
                    v.content,
                    html_escape(&v.title),
                )
            } else {
                format!(
                    "<div class=\"visual\"><h4>{}</h4><p class=\"mono\">{}</p><pre class=\"excerpt\">{}</pre></div>",
                    html_escape(&v.title),
                    html_escape(&v.file_path),
                    html_escape(&v.content),
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn notes_html(notes: &[serde_json::Value]) -> String {
    if notes.is_empty() {
        return "<p><em>No analyst notes recorded during examination</em></p>".into();
    }
    notes
        .iter()
        .map(|n| {
            let ts = n["timestamp"].as_str().unwrap_or("—");
            let body = n["body"].as_str().unwrap_or("");
            let fp = n["filePath"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| format!("<span class=\"mono\"> — {s}</span>"))
                .unwrap_or_default();
            format!(
                "<li><strong>{ts}</strong>{fp}<br/>{}</li>",
                html_escape(body)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(clippy::too_many_arguments)]
fn generate_html_report(
    case: &Case,
    timeline: &[String],
    evidence: &[String],
    findings: &[String],
    audit: &[String],
    now: &str,
    hash_chain: &integrity::HashChainReport,
    analyst_notes: &[serde_json::Value],
    visuals: &[ReportVisual],
) -> String {
    let list = |items: &[String]| -> String {
        if items.is_empty() {
            "<p><em>None recorded</em></p>".into()
        } else {
            items
                .iter()
                .map(|i| format!("<li>{}</li>", html_escape(i)))
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>AnalysisLoom Report — {name}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px;
         background: #0a0a0a; color: #e0e0e0; }}
  h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
  h2 {{ color: #3b82f6; margin-top: 28px; }}
  h4 {{ margin: 0 0 6px; font-size: 13px; }}
  .meta {{ color: #888; font-size: 13px; margin-bottom: 24px; }}
  ul {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 12px 32px; }}
  li {{ margin: 4px 0; font-size: 12px; font-family: monospace; }}
  .footer {{ margin-top: 40px; padding-top: 12px; border-top: 1px solid #222; font-size: 11px; color: #555; }}
  .pass {{ color: #22c55e; }}
  .fail {{ color: #ef4444; }}
  .warn {{ color: #f59e0b; }}
  table.chain {{ width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 8px; }}
  table.chain th, table.chain td {{ border: 1px solid #333; padding: 6px 8px; text-align: left; }}
  table.chain th {{ background: #1a1a2e; color: #93c5fd; }}
  tr.pass td {{ background: rgba(34,197,94,0.08); }}
  tr.fail td {{ background: rgba(239,68,68,0.08); }}
  .mono {{ font-family: ui-monospace, monospace; word-break: break-all; }}
  .visual {{ background: #111; border: 1px solid #333; border-radius: 8px; padding: 12px; margin: 10px 0; }}
  .visual img {{ max-width: 100%; border: 1px solid #444; border-radius: 4px; margin-top: 8px; }}
  pre.excerpt {{ background: #0d0d0d; padding: 10px; border-radius: 6px; font-size: 11px; white-space: pre-wrap; }}
  .notes li {{ font-family: inherit; list-style: none; margin: 8px 0; padding: 8px; background: #0d0d0d; border-radius: 6px; }}
</style></head>
<body>
  <h1>Forensic Analysis Report</h1>
  <div class="meta">
    <strong>Case:</strong> {name} &nbsp;|&nbsp;
    <strong>ID:</strong> {id} &nbsp;|&nbsp;
    <strong>Operator:</strong> {op} &nbsp;|&nbsp;
    <strong>Status:</strong> {status}<br/>
    <strong>Generated:</strong> {now}
  </div>

  <h2>🔗 Hash Chain Validation (NIST SP 800-86 §3.4.1)</h2>
  {hash_chain}

  <h2>⚠️ Tool Limitations (ISO 27042 §10.1)</h2>
  <ul>{limitations}</ul>

  <h2>📝 Analyst Notes (SWGDE §4.4)</h2>
  <ul class="notes">{notes}</ul>

  <h2>📸 Finding Visual Documentation</h2>
  {visuals}

  <h2>📊 Timeline Events</h2>
  <ul>{timeline}</ul>

  <h2>📦 Evidence Items</h2>
  <ul>{evidence}</ul>

  <h2>🔍 Findings</h2>
  <ul>{findings}</ul>

  <h2>📋 Audit Trail</h2>
  <ul>{audit}</ul>

  <div class="footer">
    Generated by AnalysisLoom — YSF Studio | 100% Offline Forensic Workstation<br/>
    This report is provided AS-IS. Verify independently before use in legal proceedings.<br/>
    Tool limitations and hash chain validation are documented per ISO 27042 / NIST SP 800-86 / SWGDE.
  </div>
</body></html>"#,
        name = case.name,
        id = case.id,
        op = case.operator.as_deref().unwrap_or("—"),
        status = case.status,
        now = now,
        hash_chain = integrity::hash_chain_html(hash_chain),
        limitations = report_meta::limitations_html(),
        notes = notes_html(analyst_notes),
        visuals = visuals_html(visuals),
        timeline = list(timeline),
        evidence = list(evidence),
        findings = list(findings),
        audit = list(audit),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─── Evidence Integrity (NIST SP 800-86 §3.4.1) ───

#[tauri::command]
pub fn import_hash_manifest(case_id: String, path: String) -> Result<serde_json::Value, String> {
    case_guard::ensure_case_mutable(&case_id)?;
    let manifest = integrity::parse_hash_manifest(&path)?;
    let sig_result = integrity::verify_manifest_signature(&manifest);

    if sig_result.signed && !sig_result.verified {
        return Err(format!(
            "Manifest signature verification failed — {}",
            sig_result.message
        ));
    }

    let file_count = manifest.files.len();
    let source = manifest
        .source
        .clone()
        .unwrap_or_else(|| "CollectionLoom".into());
    let json = serde_json::to_string(&manifest).map_err(|e| e.to_string())?;
    let sig_verified = if sig_result.signed && sig_result.verified {
        1
    } else {
        0
    };

    {
        let db = crate::db::conn();
        db.execute(
            "INSERT INTO case_manifest (case_id, manifest_json, source, file_count, signature_verified) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(case_id) DO UPDATE SET manifest_json = ?2, source = ?3, file_count = ?4, signature_verified = ?5, imported_at = datetime('now')",
            rusqlite::params![case_id, json, source, file_count as i64, sig_verified],
        )
        .map_err(|e| e.to_string())?;
    }

    let detail = if sig_result.verified {
        format!("hash_manifest.json — {file_count} files, Ed25519 signature verified")
    } else {
        format!("hash_manifest.json — {file_count} files (unsigned manifest)")
    };
    let _ = log_action(case_id.clone(), "IMPORT_MANIFEST".into(), detail);

    if sig_result.verified {
        let _ = log_action(
            case_id.clone(),
            "MANIFEST_SIG_OK".into(),
            sig_result.message.clone(),
        );
    }

    Ok(serde_json::json!({
        "fileCount": file_count,
        "source": source,
        "imported": true,
        "signatureVerified": sig_result.verified,
        "signed": sig_result.signed,
        "signatureMessage": sig_result.message,
    }))
}

#[tauri::command]
pub fn get_case_manifest(case_id: String) -> Result<serde_json::Value, String> {
    let db = crate::db::conn();
    let row: Result<(String, String, i64, i64), _> = db.query_row(
        "SELECT source, imported_at, file_count, COALESCE(signature_verified, 0) FROM case_manifest WHERE case_id = ?1",
        [case_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    );
    match row {
        Ok((source, imported_at, file_count, sig_verified)) => Ok(serde_json::json!({
            "loaded": true,
            "source": source,
            "importedAt": imported_at,
            "fileCount": file_count,
            "signatureVerified": sig_verified == 1,
        })),
        Err(_) => Ok(serde_json::json!({ "loaded": false })),
    }
}

#[tauri::command]
pub fn verify_evidence_integrity(
    case_id: String,
    file_path: String,
    computed_sha256: String,
) -> Result<integrity::IntegrityVerifyResult, String> {
    let manifest = load_case_manifest(&case_id);
    let result = integrity::verify_file_hash(manifest.as_ref(), &file_path, &computed_sha256);

    if !result.verified && result.expected_sha256.is_some() {
        let _ = log_action(
            case_id,
            "HASH_VERIFY_FAIL".into(),
            format!("{} — {}", file_path, result.message),
        );
    } else if result.expected_sha256.is_some() {
        let _ = log_action(
            case_id.clone(),
            "HASH_VERIFY_OK".into(),
            format!("{} — SHA-256 verified against manifest", file_path),
        );
    }

    Ok(result)
}

// ─── Analyst Notes (SWGDE §4.4) ───

#[tauri::command]
pub fn append_case_note(
    case_id: String,
    body: String,
    file_path: Option<String>,
) -> Result<i64, String> {
    case_guard::ensure_case_mutable(&case_id)?;
    let id = {
        let db = crate::db::conn();
        db.execute(
            "INSERT INTO case_notes (case_id, body, file_path) VALUES (?1, ?2, ?3)",
            rusqlite::params![case_id, body.trim(), file_path],
        )
        .map_err(|e| e.to_string())?;
        db.last_insert_rowid()
    };
    let _ = log_action(
        case_id,
        "ANALYST_NOTE".into(),
        format!("Note #{id} — {} chars", body.trim().len()),
    );
    Ok(id)
}

#[tauri::command]
pub fn list_case_notes(case_id: String) -> Result<Vec<serde_json::Value>, String> {
    list_case_notes_inner(&case_id)
}

// ─── Peer Review (ISO 27042) ───

#[tauri::command]
pub fn review_finding(
    finding_id: i64,
    status: String,
    reviewer: String,
    note: Option<String>,
) -> Result<(), String> {
    let allowed = ["approved", "rejected", "needs_revision", "pending"];
    if !allowed.contains(&status.as_str()) {
        return Err(format!("Invalid review status: {status}"));
    }

    let case_id: String = {
        let db = crate::db::conn();
        db.query_row(
            "SELECT case_id FROM findings WHERE id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("Finding not found: {e}"))?
    };

    case_guard::ensure_case_mutable(&case_id)?;

    {
        let db = crate::db::conn();
        db.execute(
            "UPDATE findings SET review_status = ?1, reviewer = ?2, reviewed_at = datetime('now'), review_note = ?3 WHERE id = ?4",
            rusqlite::params![status, reviewer, note, finding_id],
        )
        .map_err(|e| e.to_string())?;
    }

    let _ = log_action(
        case_id,
        "FINDING_REVIEW".into(),
        format!("Finding #{finding_id} → {status} by {reviewer}"),
    );
    Ok(())
}

// ─── Single Finding Export ───

fn build_single_export_html(
    title: &str,
    case_name: &str,
    file_path: &str,
    body: &str,
    meta: &str,
    visual: Option<&ReportVisual>,
) -> String {
    let visual_html = visual
        .map(|v| visuals_html(std::slice::from_ref(v)))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{title}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px;
         background: #0a0a0a; color: #e0e0e0; }}
  h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: 8px; font-size: 18px; }}
  .meta {{ color: #888; font-size: 12px; margin-bottom: 20px; }}
  .body {{ background: #111; border: 1px solid #333; border-radius: 8px; padding: 14px; font-size: 13px; }}
  .mono {{ font-family: ui-monospace, monospace; word-break: break-all; }}
  .visual {{ background: #111; border: 1px solid #333; border-radius: 8px; padding: 12px; margin: 12px 0; }}
  .visual img {{ max-width: 100%; }}
  pre.excerpt {{ background: #0d0d0d; padding: 10px; border-radius: 6px; white-space: pre-wrap; font-size: 11px; }}
</style></head><body>
  <h1>{title}</h1>
  <div class="meta"><strong>Case:</strong> {case_name}<br/><strong>File:</strong> <span class="mono">{file_path}</span><br/>{meta}</div>
  <div class="body">{body}</div>
  {visual_html}
  <p style="font-size:11px;color:#555;margin-top:32px">Exported by AnalysisLoom — YSF Studio</p>
</body></html>"#,
        title = html_escape(title),
        case_name = html_escape(case_name),
        file_path = html_escape(file_path),
        meta = html_escape(meta),
        body = html_escape(body),
        visual_html = visual_html,
    )
}

fn collect_single_visual(file_path: &str, title: &str) -> Option<ReportVisual> {
    if is_image_path(file_path) {
        if let Ok(preview) = preview::preview_file(file_path) {
            if let preview::PreviewContent::Image { data_base64, .. } = preview.preview {
                return Some(ReportVisual {
                    title: title.into(),
                    file_path: file_path.into(),
                    visual_type: "image".into(),
                    content: data_base64,
                });
            }
        }
    }
    if let Ok(preview) = preview::preview_file(file_path) {
        if let preview::PreviewContent::Text(text) = preview.preview {
            let excerpt: String = text.chars().take(1200).collect();
            return Some(ReportVisual {
                title: title.into(),
                file_path: file_path.into(),
                visual_type: "text".into(),
                content: excerpt,
            });
        }
    }
    None
}

#[tauri::command]
pub fn export_bookmark(
    case_id: String,
    bookmark_id: i64,
    output_path: String,
) -> Result<String, String> {
    let (case_name, file_path, tag, note, offset): (String, String, Option<String>, String, i64) = {
        let db = crate::db::conn();
        db.query_row(
            "SELECT c.name, b.file_path, b.tag, COALESCE(b.note,''), b.offset FROM bookmarks b JOIN cases c ON c.id = b.case_id WHERE b.id = ?1 AND b.case_id = ?2",
            rusqlite::params![bookmark_id, case_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|e| format!("Bookmark not found: {e}"))?
    };

    let title = tag.unwrap_or_else(|| "Bookmark".into());
    let meta = format!("Type: Bookmark | Offset: 0x{offset:x}");
    let body = if note.is_empty() {
        format!("Bookmarked evidence file: {file_path}")
    } else {
        note
    };
    let visual = collect_single_visual(&file_path, &title);
    let html = build_single_export_html(
        &title,
        &case_name,
        &file_path,
        &body,
        &meta,
        visual.as_ref(),
    );
    std::fs::write(&output_path, &html).map_err(|e| format!("Write error: {e}"))?;

    let _ = log_action(
        case_id,
        "EXPORT_BOOKMARK".into(),
        format!("#{bookmark_id} — {file_path}"),
    );
    Ok(output_path)
}

#[tauri::command]
pub fn export_finding(
    case_id: String,
    finding_id: i64,
    output_path: String,
) -> Result<String, String> {
    let (case_name, file_path, description, severity, review_status, reviewer): (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    ) = {
        let db = crate::db::conn();
        db.query_row(
            "SELECT c.name, f.file_path, f.description, f.severity, f.review_status, f.reviewer FROM findings f JOIN cases c ON c.id = f.case_id WHERE f.id = ?1 AND f.case_id = ?2",
            rusqlite::params![finding_id, case_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(|e| format!("Finding not found: {e}"))?
    };

    let title = format!("[{severity}] Finding");
    let meta = format!(
        "Severity: {severity} | Review: {} | Reviewer: {}",
        review_status.unwrap_or_else(|| "pending".into()),
        reviewer.unwrap_or_else(|| "—".into()),
    );
    let visual = collect_single_visual(&file_path, &description);
    let html = build_single_export_html(
        &title,
        &case_name,
        &file_path,
        &description,
        &meta,
        visual.as_ref(),
    );
    std::fs::write(&output_path, &html).map_err(|e| format!("Write error: {e}"))?;

    let _ = log_action(
        case_id,
        "EXPORT_FINDING".into(),
        format!("#{finding_id} — {file_path}"),
    );
    Ok(output_path)
}

// ─── Audit Logging ───

#[tauri::command]
pub fn log_action(case_id: String, action: String, detail: String) -> Result<(), String> {
    let db = crate::db::conn();
    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let prev_hash: String = db
        .query_row(
            "SELECT entry_hash FROM audit_log WHERE case_id = ?1 ORDER BY id DESC LIMIT 1",
            [&case_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| String::new());
    let entry_hash = integrity::audit_chain_hash(&prev_hash, &timestamp, &action, &detail);

    db.execute(
        "INSERT INTO audit_log (case_id, timestamp, action, detail, prev_hash, entry_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![case_id, timestamp, action, detail, prev_hash, entry_hash],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_audit_log(case_id: String) -> Result<Vec<serde_json::Value>, String> {
    let db = crate::db::conn();
    let mut stmt = db.prepare(
        "SELECT timestamp, action, detail FROM audit_log WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 100"
    ).map_err(|e| e.to_string())?;
    let entries = stmt
        .query_map([case_id], |row| {
            Ok(serde_json::json!({
                "timestamp": row.get::<_, String>(0)?,
                "action": row.get::<_, String>(1)?,
                "detail": row.get::<_, String>(2)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(entries)
}

// ─── Bookmarks & Tags ───

#[tauri::command]
pub fn add_bookmark(
    case_id: String,
    file_path: String,
    offset: i64,
    tag: Option<String>,
    note: Option<String>,
) -> Result<i64, String> {
    case_guard::ensure_case_mutable(&case_id)?;
    let db = crate::db::conn();
    db.execute(
        "INSERT INTO bookmarks (case_id, file_path, offset, tag, note) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![case_id, file_path, offset, tag, note],
    )
    .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

#[tauri::command]
pub fn list_bookmarks(case_id: String) -> Result<Vec<serde_json::Value>, String> {
    let db = crate::db::conn();
    let mut stmt = db.prepare(
        "SELECT id, file_path, offset, tag, note, created_at FROM bookmarks WHERE case_id = ?1 ORDER BY created_at DESC"
    ).map_err(|e| e.to_string())?;
    let bm = stmt
        .query_map([case_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "filePath": row.get::<_, String>(1)?,
                "offset": row.get::<_, i64>(2)?,
                "tag": row.get::<_, Option<String>>(3)?,
                "note": row.get::<_, Option<String>>(4)?,
                "createdAt": row.get::<_, String>(5)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(bm)
}

#[tauri::command]
pub fn delete_bookmark(id: i64) -> Result<(), String> {
    let case_id: String = crate::db::conn()
        .query_row("SELECT case_id FROM bookmarks WHERE id = ?1", [id], |row| {
            row.get(0)
        })
        .map_err(|e| format!("Bookmark not found: {e}"))?;
    case_guard::ensure_case_mutable(&case_id)?;
    crate::db::conn()
        .execute("DELETE FROM bookmarks WHERE id = ?1", [id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ─── Registry Analyzer ───

#[tauri::command]
pub fn analyze_registry_hive(path: String) -> Result<registry::RegistryScanResult, String> {
    registry::analyze_hive(&path)
}

#[tauri::command]
pub fn scan_registry_directory(dir: String) -> Result<Vec<registry::RegistryScanResult>, String> {
    registry::scan_hives_in_directory(&dir)
}

// ─── YARA Scanner ───

#[tauri::command]
pub fn yara_scan_paths(
    paths: Vec<String>,
    rules_path: Option<String>,
) -> Result<Vec<yara::YaraMatch>, String> {
    yara::scan_with_optional_rules(&paths, rules_path.as_deref())
}

#[tauri::command]
pub fn yara_builtin_rule_count() -> Result<usize, String> {
    Ok(yara::builtin_rules().len())
}

// ─── Anti-Forensics ───

#[tauri::command]
pub fn analyze_antiforensics_mft(
    image_path: String,
) -> Result<Vec<antiforensics::AntiForensicsFinding>, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let entries = ntfs::parse_mft(&image_path, &cancel)?;
    Ok(antiforensics::analyze_mft_entries(&entries, &image_path))
}

#[tauri::command]
pub fn analyze_antiforensics_files(
    paths: Vec<String>,
) -> Result<Vec<antiforensics::AntiForensicsFinding>, String> {
    Ok(antiforensics::scan_evidence_files(&paths))
}

// ─── Browser Artifacts ───

#[tauri::command]
pub fn scan_browser_artifacts(root: String) -> Result<Vec<browser::BrowserScanResult>, String> {
    browser::scan_browser_artifacts(&root)
}

#[tauri::command]
pub fn analyze_browser_db(path: String) -> Result<browser::BrowserScanResult, String> {
    browser::analyze_browser_db(&path)
}

// ─── NSRL Lookup ───

#[tauri::command]
pub fn nsrl_lookup_file(path: String) -> Result<nsrl::NsrlLookupResult, String> {
    nsrl::lookup_file(&path)
}

#[tauri::command]
pub fn nsrl_lookup_hash(sha256: String) -> Result<nsrl::NsrlLookupResult, String> {
    nsrl::lookup_sha256(&sha256)
}

#[tauri::command]
pub fn nsrl_import(path: String) -> Result<usize, String> {
    nsrl::import_nsrl_file(&path)
}

#[tauri::command]
pub fn nsrl_seed_builtin() -> Result<usize, String> {
    nsrl::seed_builtin_nsrl()
}

#[tauri::command]
pub fn nsrl_stats() -> Result<serde_json::Value, String> {
    nsrl::nsrl_stats()
}

// ─── Memory / Volatility Bridge ───

#[tauri::command]
pub fn parse_volatility_json(path: String) -> Result<memory::MemoryAnalysisResult, String> {
    memory::parse_volatility_json(&path)
}

// ─── Super Timeline ───

#[tauri::command]
pub fn get_super_timeline(case_id: String) -> Result<Vec<timeline::SuperTimelineEvent>, String> {
    timeline::build_super_timeline(&case_id)
}

// ─── Deleted file recovery ───

#[tauri::command]
pub fn list_deleted_mft(image_path: String) -> Result<Vec<ntfs::MftEntry>, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let entries = ntfs::parse_mft(&image_path, &cancel)?;
    Ok(entries.into_iter().filter(|e| e.is_deleted).collect())
}

#[tauri::command]
pub fn recover_deleted_carve(
    image_path: String,
    output_dir: String,
) -> Result<carving::CarvingResult, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    carving::carve_files(&image_path, &output_dir, &cancel)
}

// ─── V2: Windows EVTX ───

#[tauri::command]
pub fn parse_evtx_log(path: String) -> Result<evtx::EvtxScanResult, String> {
    evtx::parse_evtx_file(&path)
}

#[tauri::command]
pub fn scan_evtx_directory(dir: String) -> Result<Vec<evtx::EvtxScanResult>, String> {
    evtx::scan_evtx_directory(&dir)
}

// ─── V2: macOS Artifacts ───

#[tauri::command]
pub fn scan_macos_artifacts(root: String) -> Result<Vec<macos::MacosScanResult>, String> {
    macos::scan_macos_artifacts(&root)
}

#[tauri::command]
pub fn analyze_macos_plist(path: String) -> Result<macos::MacosScanResult, String> {
    macos::analyze_macos_plist(&path)
}

// ─── V2: PCAP Network ───

#[tauri::command]
pub fn analyze_pcap(path: String) -> Result<pcap::PcapScanResult, String> {
    pcap::analyze_pcap(&path)
}

// ─── V2.1: Windows Artifacts ───

#[tauri::command]
pub fn scan_windows_artifacts(
    root: String,
) -> Result<windows_artifacts::WindowsScanResult, String> {
    windows_artifacts::scan_windows_artifacts(&root)
}

// ─── V2.1: Steganography ───

#[tauri::command]
pub fn scan_steganography(paths: Vec<String>) -> Result<steganography::StegoScanResult, String> {
    Ok(steganography::scan_images(&paths))
}

#[tauri::command]
pub fn analyze_steganography(path: String) -> Result<steganography::StegoFinding, String> {
    steganography::analyze_image(&path)
}

// ─── V2.1: Email Forensics ───

#[tauri::command]
pub fn scan_email_directory(dir: String) -> Result<Vec<email::EmailScanResult>, String> {
    email::scan_email_directory(&dir)
}

// ─── V2.1: Chat Artifacts ───

#[tauri::command]
pub fn scan_chat_artifacts(root: String) -> Result<Vec<chat::ChatScanResult>, String> {
    chat::scan_chat_artifacts(&root)
}

// ─── V2.1: Linux Artifacts ───

#[tauri::command]
pub fn scan_linux_artifacts(root: String) -> Result<linux::LinuxScanResult, String> {
    linux::scan_linux_artifacts(&root)
}

// ─── V2.2: Cross-Platform Acquisition ───

#[tauri::command]
pub fn detect_evidence_platform(root: String) -> Result<acquisition::PlatformDetection, String> {
    acquisition::detect_platform(&root)
}

#[tauri::command]
pub fn scan_acquisition(
    root: String,
    case_id: Option<String>,
) -> Result<acquisition::AcquisitionScanResult, String> {
    acquisition::scan_acquisition(&root, case_id.as_deref())
}

// ─── V2.1: Plugin SDK ───

#[tauri::command]
pub fn list_forensic_plugins() -> Vec<plugins::PluginInfo> {
    plugins::list_plugins()
}

#[tauri::command]
pub fn run_forensic_plugin(plugin_id: String, path: String) -> plugins::PluginRunResult {
    plugins::run_plugin(&plugin_id, &path)
}

// ─── V2: Evidence Bundle Export ───

fn bundle_pdf_bytes(
    case: &Case,
    case_id: &str,
    timeline: &[String],
    evidence_lines: &[String],
    hash_chain: &integrity::HashChainReport,
    now: &str,
) -> Option<Vec<u8>> {
    let sections = vec![
        report::ReportSection {
            heading: "Case Information".into(),
            content: format!(
                "Case: {}\nOperator: {}\nStatus: {}\nCreated: {}",
                case.name,
                case.operator.clone().unwrap_or_default(),
                case.status,
                case.created_at
            ),
        },
        report::ReportSection {
            heading: "Timeline".into(),
            content: timeline.join("\n"),
        },
        report::ReportSection {
            heading: "Evidence".into(),
            content: evidence_lines.join("\n"),
        },
        report::ReportSection {
            heading: "Tool Limitations (ISO 27042 §10.1)".into(),
            content: report_meta::limitations_text(),
        },
        report::ReportSection {
            heading: "Hash Chain Validation".into(),
            content: integrity::hash_chain_text(hash_chain),
        },
    ];
    report::generate_pdf_report(&report::PdfReport {
        title: format!("Forensic Analysis Report — {}", case.name),
        evidence_id: case_id.to_string(),
        operator: case.operator.clone().unwrap_or_default(),
        case_name: case.name.clone(),
        device: "AnalysisLoom Workstation".into(),
        date: now.to_string(),
        sections,
    })
    .ok()
}

#[tauri::command]
pub fn export_case_bundle(
    case_id: String,
    output_path: String,
) -> Result<bundle::BundleExportResult, String> {
    let (
        case,
        evidence_rows,
        findings_json,
        audit_json,
        timeline,
        evidence_lines,
        finding_lines,
        audit_lines,
    ) = {
        let db = crate::db::conn();

        let case: Case = db
        .query_row(
            "SELECT id, name, operator, created_at, status, sealed_at, sealed_by, seal_hash FROM cases WHERE id = ?1",
            [&case_id],
            |row| {
                Ok(Case {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    operator: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
                    sealed_at: row.get(5)?,
                    sealed_by: row.get(6)?,
                    seal_hash: row.get(7)?,
                })
            },
        )
        .map_err(|e| format!("Case not found: {e}"))?;

        let mut estmt = db
        .prepare("SELECT source_path, type, sha256, size_bytes FROM evidence_items WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
        let evidence_rows: Vec<(String, String, Option<String>, i64)> = estmt
            .query_map([&case_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3).unwrap_or(0),
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        let mut fstmt = db
            .prepare("SELECT id, description, file_path, severity FROM findings WHERE case_id = ?1")
            .map_err(|e| e.to_string())?;
        let findings: Vec<serde_json::Value> = fstmt
            .query_map([&case_id], |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, i64>(0)?,
                    "description": row.get::<_, String>(1)?,
                    "filePath": row.get::<_, String>(2)?,
                    "severity": row.get::<_, String>(3)?,
                }))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();
        let findings_json = serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())?;

        let mut astmt = db.prepare(
        "SELECT timestamp, action, detail FROM audit_log WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 100",
    ).map_err(|e| e.to_string())?;
        let audit: Vec<serde_json::Value> = astmt
            .query_map([&case_id], |row| {
                Ok(serde_json::json!({
                    "timestamp": row.get::<_, String>(0)?,
                    "action": row.get::<_, String>(1)?,
                    "detail": row.get::<_, String>(2)?,
                }))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();
        let audit_json = serde_json::to_string_pretty(&audit).map_err(|e| e.to_string())?;

        let mut tstmt = db.prepare(
        "SELECT timestamp, source, file_path, event_type FROM timeline_events WHERE case_id = ?1 ORDER BY timestamp DESC LIMIT 100",
    ).map_err(|e| e.to_string())?;
        let timeline: Vec<String> = tstmt
            .query_map([&case_id], |row| {
                Ok(format!(
                    "{} | {} | {} ({})",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(1)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        let evidence_lines: Vec<String> = evidence_rows
            .iter()
            .map(|(p, t, sha, sz)| {
                format!(
                    "{} ({}) — {} bytes — SHA256: {}",
                    p,
                    t,
                    sz,
                    sha.clone().unwrap_or_default()
                )
            })
            .collect();

        let finding_lines: Vec<String> = findings
            .iter()
            .filter_map(|f| {
                Some(format!(
                    "[{}] {} — {}",
                    f.get("severity")?.as_str()?,
                    f.get("description")?.as_str()?,
                    f.get("filePath")?.as_str()?,
                ))
            })
            .collect();

        let audit_lines: Vec<String> = audit
            .iter()
            .filter_map(|a| {
                Some(format!(
                    "{} | {} — {}",
                    a.get("timestamp")?.as_str()?,
                    a.get("action")?.as_str()?,
                    a.get("detail")?.as_str()?,
                ))
            })
            .collect();

        (
            case,
            evidence_rows,
            findings_json,
            audit_json,
            timeline,
            evidence_lines,
            finding_lines,
            audit_lines,
        )
    };

    let manifest = load_case_manifest(&case_id);
    let evidence_paths: Vec<(String, Option<String>)> = evidence_rows
        .iter()
        .map(|(p, _, sha, _)| (p.clone(), sha.clone()))
        .collect();
    let hash_chain = integrity::build_hash_chain_report(manifest.as_ref(), &evidence_paths);
    let analyst_notes = list_case_notes_inner(&case_id)?;
    let visuals = collect_report_visuals(&case_id)?;

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let html = generate_html_report(
        &case,
        &timeline,
        &evidence_lines,
        &finding_lines,
        &audit_lines,
        &now,
        &hash_chain,
        &analyst_notes,
        &visuals,
    );

    let pdf_bytes = bundle_pdf_bytes(
        &case,
        &case_id,
        &timeline,
        &evidence_lines,
        &hash_chain,
        &now,
    );

    let operator = case.operator.clone().unwrap_or_else(|| "Analyst".into());
    let result = bundle::create_case_bundle(
        &case_id,
        &case.name,
        &operator,
        &output_path,
        &evidence_rows,
        &html,
        pdf_bytes.as_deref(),
        &findings_json,
        &audit_json,
    )?;

    log_action(
        case_id,
        "EXPORT_BUNDLE".into(),
        format!(
            "{} files, manifest {}",
            result.file_count, result.manifest_sha256
        ),
    )?;

    Ok(result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoFixtures {
    pub ntfs: String,
    pub luks: String,
    pub carve: String,
    pub sqlite: String,
    pub evidence: String,
    pub png: String,
}

/// Returns fixture paths when `ANALYSISLOOM_SCREENSHOT=1` (for automated screenshots).
#[tauri::command]
pub fn demo_fixtures() -> Option<DemoFixtures> {
    if std::env::var("ANALYSISLOOM_SCREENSHOT").is_err() {
        return None;
    }
    let dir = std::env::var("ANALYSISLOOM_FIXTURES_DIR").ok()?;
    let base = std::path::Path::new(&dir);
    if !base.is_dir() {
        return None;
    }
    Some(DemoFixtures {
        ntfs: base.join("random_ntfs.dd").to_string_lossy().into(),
        luks: base.join("luks_volume.dd").to_string_lossy().into(),
        carve: base.join("carve_source.dd").to_string_lossy().into(),
        sqlite: base.join("messages.db").to_string_lossy().into(),
        evidence: base
            .join("secret_password_log.txt")
            .to_string_lossy()
            .into(),
        png: base.join("photo_evidence.png").to_string_lossy().into(),
    })
}

#[tauri::command]
pub fn about_info() -> serde_json::Value {
    serde_json::json!({
        "appName": "AnalysisLoom",
        "version": "0.1.0",
        "developer": "YSF Studio — Built with ❤️ by Yusuf Shalahuddin",
        "build": "Forensic Workstation — All Modules Unlocked",
        "features": [
            "Forensic-grade NTFS/MFT Parser & File Browser",
            "File Carving with multi-format signature detection",
            "Super Timeline — multi-source event correlation",
            "Windows EVTX Event Log Parser (4624/4625/4688/4104)",
            "macOS Artifact Analyzer (plist, KnowledgeC, Unified Logs)",
            "PCAP Network Analyzer (TCP/UDP/DNS flow reconstruction)",
            "Evidence Bundle ZIP Export (files + manifest + report)",
            "Registry Analyzer (SAM / SYSTEM / SOFTWARE / NTUSER.DAT)",
            "Built-in YARA Scanner with custom .yar rule loading",
            "Anti-Forensics Detection (timestomp, ADS, extension mismatch)",
            "Browser Artifacts (Chrome, Firefox, Safari, Edge)",
            "NSRL Known-Good Hash Lookup",
            "Memory Analysis Bridge (Volatility 3 JSON import)",
            "Hex & Keyword Search across case evidence",
            "SQLite Artifact Browser & Case Management with Audit Trail",
            "Encrypted Volume Detection (LUKS, BitLocker, high-entropy)",
            "Windows Artifacts — Prefetch, LNK, Jump Lists",
            "Steganography Detection — LSB analysis & metadata anomalies",
            "Email Forensics — PST/OST mailbox parsing",
            "Chat Artifacts — WhatsApp, Telegram, Signal SQLite",
            "Linux Artifacts — auditd, auth.log, bash history",
            "Plugin SDK — extensible forensic plugin trait",
            "Timeline Gantt — graphical multi-source visualization",
            "Cross-Platform Acquisition — auto-detect Windows/Linux/macOS evidence folders",
            "100% Offline — Zero Data Collection. All processing runs locally."
        ],
        "disclaimer": "This software is provided 'AS-IS'. Results should be independently verified before use in legal proceedings.",
        "offline": true,
        "privacy": "100% offline — zero data collection. No telemetry, no analytics, no external network calls."
    })
}
