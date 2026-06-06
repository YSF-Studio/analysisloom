//! macOS artifact analyzer — plist, KnowledgeC, Unified Logs, Spotlight.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosArtifact {
    pub artifact_type: String,
    pub path: String,
    pub key: String,
    pub value: String,
    pub timestamp: String,
    pub category: String,
    pub forensic_relevance: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosScanResult {
    pub source_path: String,
    pub artifacts: Vec<MacosArtifact>,
    pub sources_scanned: usize,
}

const ARTIFACT_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "KnowledgeC.db",
        "user_activity",
        "KnowledgeC — user activity timeline",
    ),
    ("History.db", "browser", "Safari browsing history"),
    (".logarchive", "unified_log", "macOS Unified Log archive"),
    (
        "DataDetectors",
        "datadetectors",
        "DataDetectors contact/address extraction",
    ),
    ("Spotlight", "spotlight", "Spotlight index / search history"),
    (
        "TCC.db",
        "privacy",
        "Transparency, Consent, Control permissions",
    ),
    (
        "LSSharedFileList",
        "recent",
        "Recent documents / shared file lists",
    ),
    (
        "com.apple.loginwindow",
        "login",
        "Login window / session artifacts",
    ),
];

pub fn scan_macos_artifacts(root: &str) -> Result<Vec<MacosScanResult>, String> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(format!("Path not found: {root}"));
    }

    let mut results = vec![];
    let mut scanned = 0usize;

    for (pattern, category, relevance) in ARTIFACT_PATTERNS {
        for hit in find_artifacts(root_path, pattern, 0, 6) {
            scanned += 1;
            let artifacts = match hit.extension().and_then(|e| e.to_str()) {
                Some("plist") => {
                    analyze_plist_file(hit.to_string_lossy().as_ref(), category, relevance)
                }
                Some("db") | Some("sqlite") | Some("sqlite3") => {
                    analyze_sqlite_artifact(hit.to_string_lossy().as_ref(), category, relevance)
                }
                _ if hit.to_string_lossy().contains(".logarchive") || hit.is_dir() => {
                    vec![MacosArtifact {
                        artifact_type: "unified_log".into(),
                        path: hit.to_string_lossy().into(),
                        key: "logarchive".into(),
                        value: "Unified Log archive detected".into(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        category: (*category).to_string(),
                        forensic_relevance: (*relevance).to_string(),
                    }]
                }
                _ => vec![MacosArtifact {
                    artifact_type: (*category).to_string(),
                    path: hit.to_string_lossy().into(),
                    key: (*pattern).to_string(),
                    value: "Artifact path match".into(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    category: (*category).to_string(),
                    forensic_relevance: (*relevance).to_string(),
                }],
            };

            if !artifacts.is_empty() {
                results.push(MacosScanResult {
                    source_path: hit.to_string_lossy().into(),
                    artifacts,
                    sources_scanned: 1,
                });
            }
        }
    }

    if results.is_empty() {
        results.push(MacosScanResult {
            source_path: root.into(),
            artifacts: vec![MacosArtifact {
                artifact_type: "scan".into(),
                path: root.into(),
                key: "(scan)".into(),
                value: format!("Scanned {scanned} paths — no macOS artifacts matched"),
                timestamp: chrono::Utc::now().to_rfc3339(),
                category: "general".into(),
                forensic_relevance: "Directory scan complete".into(),
            }],
            sources_scanned: scanned,
        });
    }

    Ok(results)
}

pub fn analyze_macos_plist(path: &str) -> Result<MacosScanResult, String> {
    let artifacts = analyze_plist_file(path, "plist", "macOS Preferences plist");
    Ok(MacosScanResult {
        source_path: path.into(),
        artifacts,
        sources_scanned: 1,
    })
}

fn find_artifacts(dir: &Path, pattern: &str, depth: u8, max: u8) -> Vec<std::path::PathBuf> {
    let mut hits = vec![];
    if depth > max {
        return hits;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains(pattern) || path.to_string_lossy().contains(pattern) {
            hits.push(path.clone());
        }
        if path.is_dir() {
            hits.extend(find_artifacts(&path, pattern, depth + 1, max));
        }
    }
    hits
}

fn analyze_plist_file(path: &str, category: &str, relevance: &str) -> Vec<MacosArtifact> {
    let Ok(data) = std::fs::read(path) else {
        return vec![];
    };
    let value: plist::Value = match plist::from_bytes(&data) {
        Ok(v) => v,
        Err(_) => {
            use std::io::Cursor;
            match plist::from_reader_xml(Cursor::new(&data)) {
                Ok(v) => v,
                Err(e) => {
                    return vec![MacosArtifact {
                        artifact_type: "plist".into(),
                        path: path.into(),
                        key: "(error)".into(),
                        value: format!("Parse error: {e}"),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        category: (*category).to_string(),
                        forensic_relevance: (*relevance).to_string(),
                    }];
                }
            }
        }
    };

    flatten_plist(&value, path, category, relevance, "", 0)
}

fn flatten_plist(
    value: &plist::Value,
    path: &str,
    category: &str,
    relevance: &str,
    prefix: &str,
    depth: u8,
) -> Vec<MacosArtifact> {
    let mut out = vec![];
    if depth > 4 {
        return out;
    }
    if let plist::Value::Dictionary(map) = value {
        for (k, v) in map {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            if matches!(
                v,
                plist::Value::String(_) | plist::Value::Integer(_) | plist::Value::Boolean(_)
            ) {
                out.push(MacosArtifact {
                    artifact_type: "plist".into(),
                    path: path.into(),
                    key: key.clone(),
                    value: format!("{v:?}").trim_matches('"').to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    category: (*category).to_string(),
                    forensic_relevance: (*relevance).to_string(),
                });
            } else {
                out.extend(flatten_plist(v, path, category, relevance, &key, depth + 1));
            }
            if out.len() >= 50 {
                break;
            }
        }
    }
    out
}

fn analyze_sqlite_artifact(path: &str, category: &str, relevance: &str) -> Vec<MacosArtifact> {
    let conn = match rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => {
            return vec![MacosArtifact {
                artifact_type: category.into(),
                path: path.into(),
                key: "(error)".into(),
                value: e.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                category: category.into(),
                forensic_relevance: relevance.into(),
            }];
        }
    };

    let fname = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if fname.contains("KnowledgeC") {
        return query_knowledgec(&conn, path, relevance);
    }

    let mut artifacts = vec![];
    if let Ok(mut stmt) =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 10")
    {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for table in rows.flatten() {
                artifacts.push(MacosArtifact {
                    artifact_type: category.into(),
                    path: path.into(),
                    key: table,
                    value: "SQLite table".into(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    category: category.into(),
                    forensic_relevance: relevance.into(),
                });
            }
        }
    }
    artifacts
}

fn query_knowledgec(
    conn: &rusqlite::Connection,
    path: &str,
    relevance: &str,
) -> Vec<MacosArtifact> {
    let queries = [
        "SELECT ZSTARTDATE, ZSTREAMNAME FROM ZOBJECT ORDER BY ZSTARTDATE DESC LIMIT 20",
        "SELECT ZTITLE, ZURL FROM ZHISTORYITEM LIMIT 20",
    ];
    let mut artifacts = vec![];
    for q in queries {
        if let Ok(mut stmt) = conn.prepare(q) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                ))
            }) {
                for row in rows.flatten() {
                    artifacts.push(MacosArtifact {
                        artifact_type: "user_activity".into(),
                        path: path.into(),
                        key: row.0.unwrap_or_default(),
                        value: row.1.unwrap_or_default(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        category: "knowledgec".into(),
                        forensic_relevance: relevance.into(),
                    });
                }
            }
        }
    }
    artifacts
}
