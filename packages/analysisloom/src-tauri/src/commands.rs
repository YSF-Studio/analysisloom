use crate::forensic::{
    self, antiforensics, browser, bundle, carving, encryption, evidence, evtx, hashing, macos,
    memory, nsrl, ntfs, pcap, preview, registry, report, sqlite, timeline, yara, ProgressState,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub name: String,
    pub operator: Option<String>,
    pub created_at: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub file_path: String,
    pub offset: u64,
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
            "SELECT id, name, operator, created_at, status FROM cases ORDER BY created_at DESC",
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
    })
}

#[tauri::command]
pub fn get_case(id: String) -> Result<Case, String> {
    let db = crate::db::conn();
    db.query_row(
        "SELECT id, name, operator, created_at, status FROM cases WHERE id = ?1",
        [&id],
        |row| {
            Ok(Case {
                id: row.get(0)?,
                name: row.get(1)?,
                operator: row.get(2)?,
                created_at: row.get(3)?,
                status: row.get(4)?,
            })
        },
    )
    .map_err(|e| e.to_string())
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
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE case_id = ?1"),
            [&id],
        )
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
            "SELECT id, description, file_path, severity FROM findings WHERE case_id = ?1 ORDER BY id DESC",
        )
        .map_err(|e| e.to_string())?;
    let items = stmt
        .query_map([case_id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                description: row.get(1)?,
                file_path: row.get(2)?,
                severity: row.get(3)?,
                created_at: None,
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
    let db = crate::db::conn();

    // Get case info
    let case: Case = db
        .query_row(
            "SELECT id, name, operator, created_at, status FROM cases WHERE id = ?1",
            [&case_id],
            |row| {
                Ok(Case {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    operator: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
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
        .prepare("SELECT description, file_path, severity FROM findings WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
    let findings: Vec<String> = stmt
        .query_map([&case_id], |row| {
            Ok(format!(
                "[{}] {} — {}",
                row.get::<_, String>(2)?,
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
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

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let operator_name = case.operator.clone().unwrap_or_default();

    if format == "html" {
        // Generate HTML report
        let html = generate_html_report(&case, &timeline, &evidence, &findings, &audit, &now);
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

fn generate_html_report(
    case: &Case,
    timeline: &[String],
    evidence: &[String],
    findings: &[String],
    audit: &[String],
    now: &str,
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
  body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px;
         background: #0a0a0a; color: #e0e0e0; }}
  h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
  h2 {{ color: #3b82f6; margin-top: 28px; }}
  .meta {{ color: #888; font-size: 13px; margin-bottom: 24px; }}
  ul {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 12px 32px; }}
  li {{ margin: 4px 0; font-size: 12px; font-family: monospace; }}
  .footer {{ margin-top: 40px; padding-top: 12px; border-top: 1px solid #222; font-size: 11px; color: #555; }}
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
    This report is provided AS-IS. Verify independently before use in legal proceedings.
  </div>
</body></html>"#,
        name = case.name,
        id = case.id,
        op = case.operator.as_deref().unwrap_or("—"),
        status = case.status,
        now = now,
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

// ─── Audit Logging ───

#[tauri::command]
pub fn log_action(case_id: String, action: String, detail: String) -> Result<(), String> {
    crate::db::conn()
        .execute(
            "INSERT INTO audit_log (case_id, action, detail) VALUES (?1, ?2, ?3)",
            rusqlite::params![case_id, action, detail],
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
pub fn yara_scan_paths(paths: Vec<String>, rules_path: Option<String>) -> Result<Vec<yara::YaraMatch>, String> {
    yara::scan_with_optional_rules(&paths, rules_path.as_deref())
}

#[tauri::command]
pub fn yara_builtin_rule_count() -> Result<usize, String> {
    Ok(yara::builtin_rules().len())
}

// ─── Anti-Forensics ───

#[tauri::command]
pub fn analyze_antiforensics_mft(image_path: String) -> Result<Vec<antiforensics::AntiForensicsFinding>, String> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let entries = ntfs::parse_mft(&image_path, &cancel)?;
    Ok(antiforensics::analyze_mft_entries(&entries, &image_path))
}

#[tauri::command]
pub fn analyze_antiforensics_files(paths: Vec<String>) -> Result<Vec<antiforensics::AntiForensicsFinding>, String> {
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
pub fn recover_deleted_carve(image_path: String, output_dir: String) -> Result<carving::CarvingResult, String> {
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

// ─── V2: Evidence Bundle Export ───

#[tauri::command]
pub fn export_case_bundle(case_id: String, output_path: String) -> Result<bundle::BundleExportResult, String> {
    let (case, evidence_rows, findings_json, audit_json, timeline, evidence_lines, finding_lines, audit_lines) = {
        let db = crate::db::conn();

        let case: Case = db
        .query_row(
            "SELECT id, name, operator, created_at, status FROM cases WHERE id = ?1",
            [&case_id],
            |row| {
                Ok(Case {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    operator: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
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
    let findings_json =
        serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())?;

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

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let html = generate_html_report(&case, &timeline, &evidence_lines, &finding_lines, &audit_lines, &now);

    let pdf_bytes = (|| {
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
        ];
        report::generate_pdf_report(&report::PdfReport {
            title: format!("Forensic Analysis Report — {}", case.name),
            evidence_id: case_id.clone(),
            operator: case.operator.clone().unwrap_or_default(),
            case_name: case.name.clone(),
            device: "AnalysisLoom Workstation".into(),
            date: now.clone(),
            sections,
        })
        .ok()
    })();

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
        evidence: base.join("secret_password_log.txt").to_string_lossy().into(),
        png: base.join("photo_evidence.png").to_string_lossy().into(),
    })
}

#[tauri::command]
pub fn about_info() -> serde_json::Value {
    serde_json::json!({
        "appName": "AnalysisLoom",
        "version": "0.1.0",
        "developer": "YSF Studio — Built with ❤️ by Yusuf Shalahuddin",
        "build": "V2 Forensic Workstation — All Features Unlocked",
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
            "100% Offline — Zero Data Collection. All processing runs locally."
        ],
        "disclaimer": "This software is provided 'AS-IS'. Results should be independently verified before use in legal proceedings.",
        "offline": true,
        "privacy": "100% offline — zero data collection. No telemetry, no analytics, no external network calls."
    })
}
