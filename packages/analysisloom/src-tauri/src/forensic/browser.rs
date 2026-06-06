//! Browser artifacts: Chrome, Firefox, Safari history/bookmarks/downloads.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifact {
    pub browser: String,
    pub artifact_type: String,
    pub url: String,
    pub title: String,
    pub visit_count: u64,
    pub last_visit: String,
    pub source_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScanResult {
    pub browser: String,
    pub artifacts: Vec<BrowserArtifact>,
    pub db_path: String,
}

pub fn detect_browser_dbs(root: &str) -> Vec<(String, String)> {
    let mut found = vec![];
    let root = Path::new(root);
    if !root.exists() {
        return found;
    }

    let patterns: Vec<(&str, &str, &str)> = vec![
        ("Chrome", "History", "Google/Chrome/User Data/Default/History"),
        ("Chrome", "History", "Google/Chrome/User Data/Profile 1/History"),
        ("Firefox", "places.sqlite", "Mozilla/Firefox/Profiles"),
        ("Safari", "History.db", "Safari/History.db"),
        ("Edge", "History", "Microsoft/Edge/User Data/Default/History"),
    ];

    for (browser, file, rel) in patterns {
        let direct = root.join(rel);
        if direct.is_file() {
            found.push((browser.to_string(), direct.to_string_lossy().into()));
            continue;
        }
        if rel.contains("Profiles") {
            if let Ok(entries) = std::fs::read_dir(root.join("Mozilla/Firefox/Profiles")) {
                for entry in entries.flatten() {
                    let p = entry.path().join(file);
                    if p.is_file() {
                        found.push((browser.to_string(), p.to_string_lossy().into()));
                    }
                }
            }
        }
    }

    // Flat scan for History / places.sqlite in directory tree (depth 4)
    scan_for_files(root, &["History", "places.sqlite", "History.db"], 0, 4, &mut found);
    found
}

fn scan_for_files(dir: &Path, names: &[&str], depth: u8, max: u8, out: &mut Vec<(String, String)>) {
    if depth > max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if names.iter().any(|n| fname.eq_ignore_ascii_case(n) || fname.contains(n)) {
                let browser = if path.to_string_lossy().contains("Chrome") {
                    "Chrome"
                } else if path.to_string_lossy().contains("Firefox") {
                    "Firefox"
                } else if path.to_string_lossy().contains("Safari") {
                    "Safari"
                } else if path.to_string_lossy().contains("Edge") {
                    "Edge"
                } else {
                    "Unknown"
                };
                out.push((browser.to_string(), path.to_string_lossy().into()));
            }
        } else if path.is_dir() {
            scan_for_files(&path, names, depth + 1, max, out);
        }
    }
}

pub fn analyze_browser_db(db_path: &str) -> Result<BrowserScanResult, String> {
    let browser = if db_path.contains("Chrome") || db_path.contains("Edge") {
        if db_path.contains("Edge") {
            "Edge"
        } else {
            "Chrome"
        }
    } else if db_path.contains("Firefox") || db_path.contains("places") {
        "Firefox"
    } else if db_path.contains("Safari") {
        "Safari"
    } else {
        "Chromium"
    };

    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("Cannot open browser DB: {e}"))?;

    let artifacts = match browser {
        "Firefox" => parse_firefox(&conn, db_path)?,
        "Safari" => parse_safari(&conn, db_path)?,
        _ => parse_chromium(&conn, db_path, browser)?,
    };

    Ok(BrowserScanResult {
        browser: browser.into(),
        artifacts,
        db_path: db_path.into(),
    })
}

fn parse_chromium(
    conn: &rusqlite::Connection,
    db_path: &str,
    browser: &str,
) -> Result<Vec<BrowserArtifact>, String> {
    let mut artifacts = vec![];
    let query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
    if let Ok(mut stmt) = conn.prepare(query) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            artifacts.push(BrowserArtifact {
                browser: browser.into(),
                artifact_type: "history".into(),
                url: row.0,
                title: row.1,
                visit_count: row.2 as u64,
                last_visit: chromium_time(row.3),
                source_path: db_path.into(),
            });
        }
    }

    if let Ok(mut stmt) = conn.prepare(
        "SELECT target_path, tab_url, start_time FROM downloads ORDER BY start_time DESC LIMIT 50",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        }) {
            for row in rows.flatten() {
                artifacts.push(BrowserArtifact {
                    browser: browser.into(),
                    artifact_type: "download".into(),
                    url: row.1,
                    title: row.0,
                    visit_count: 1,
                    last_visit: chromium_time(row.2),
                    source_path: db_path.into(),
                });
            }
        }
    }
    Ok(artifacts)
}

fn parse_firefox(conn: &rusqlite::Connection, db_path: &str) -> Result<Vec<BrowserArtifact>, String> {
    let mut artifacts = vec![];
    let query = r#"
        SELECT p.url, p.title, p.visit_count, h.visit_date
        FROM moz_places p
        LEFT JOIN moz_historyvisits h ON p.id = h.place_id
        ORDER BY h.visit_date DESC LIMIT 100
    "#;
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        }) {
            for row in rows.flatten() {
                artifacts.push(BrowserArtifact {
                    browser: "Firefox".into(),
                    artifact_type: "history".into(),
                    url: row.0,
                    title: row.1.unwrap_or_default(),
                    visit_count: row.2 as u64,
                    last_visit: firefox_time(row.3.unwrap_or(0)),
                    source_path: db_path.into(),
                });
            }
        }
    }
    Ok(artifacts)
}

fn parse_safari(conn: &rusqlite::Connection, db_path: &str) -> Result<Vec<BrowserArtifact>, String> {
    let mut artifacts = vec![];
    let queries = [
        "SELECT url, title, visit_count, visit_time FROM history_items LIMIT 100",
        "SELECT url, title, 1, visit_time FROM history_visits LIMIT 100",
    ];
    for q in queries {
        if let Ok(mut stmt) = conn.prepare(q) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, f64>(3)?,
                ))
            }) {
                for row in rows.flatten() {
                    artifacts.push(BrowserArtifact {
                        browser: "Safari".into(),
                        artifact_type: "history".into(),
                        url: row.0,
                        title: row.1,
                        visit_count: row.2 as u64,
                        last_visit: format!("{:.0}", row.3),
                        source_path: db_path.into(),
                    });
                }
            }
            if !artifacts.is_empty() {
                break;
            }
        }
    }
    Ok(artifacts)
}

fn chromium_time(webkit_us: i64) -> String {
    if webkit_us <= 0 {
        return "unknown".into();
    }
    let unix = webkit_us / 1_000_000 - 11_644_473_600;
    if let Some(dt) = chrono::DateTime::from_timestamp(unix, 0) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "invalid".into()
    }
}

fn firefox_time(micro: i64) -> String {
    if micro <= 0 {
        return "unknown".into();
    }
    let unix = micro / 1_000_000;
    if let Some(dt) = chrono::DateTime::from_timestamp(unix, 0) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "invalid".into()
    }
}

pub fn scan_browser_artifacts(root: &str) -> Result<Vec<BrowserScanResult>, String> {
    let dbs = detect_browser_dbs(root);
    let mut results = vec![];
    for (_browser, path) in dbs {
        if let Ok(r) = analyze_browser_db(&path) {
            if !r.artifacts.is_empty() {
                results.push(r);
            }
        }
    }
    Ok(results)
}
