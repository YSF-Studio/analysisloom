//! Chat artifact analysis — WhatsApp, Telegram, Signal SQLite databases.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub platform: String,
    pub chat_id: String,
    pub sender: String,
    pub message: String,
    pub timestamp: String,
    pub message_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatScanResult {
    pub platform: String,
    pub db_path: String,
    pub messages: Vec<ChatMessage>,
    pub message_count: usize,
}

pub fn scan_chat_artifacts(root: &str) -> Result<Vec<ChatScanResult>, String> {
    let root = Path::new(root);
    if !root.exists() {
        return Err(format!("Path not found: {}", root.display()));
    }
    let mut dbs = vec![];
    find_chat_dbs(root, 0, 6, &mut dbs);

    let mut results = vec![];
    for (platform, path) in dbs {
        if let Ok(r) = analyze_chat_db(&platform, &path) {
            results.push(r);
        }
    }
    Ok(results)
}

fn find_chat_dbs(dir: &Path, depth: u8, max: u8, out: &mut Vec<(String, String)>) {
    if depth > max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                let full = path.to_string_lossy().to_lowercase();
                let platform = if lower == "msgstore.db" || full.contains("whatsapp") {
                    "WhatsApp"
                } else if lower == "cache4.db" || full.contains("telegram") {
                    "Telegram"
                } else if lower.contains("signal") && lower.ends_with(".db") {
                    "Signal"
                } else if lower == "messages.db" && full.contains("chat") {
                    "Generic Chat"
                } else {
                    continue;
                };
                out.push((platform.into(), path.to_string_lossy().into()));
            }
        } else if path.is_dir() {
            find_chat_dbs(&path, depth + 1, max, out);
        }
    }
}

pub fn analyze_chat_db(platform: &str, db_path: &str) -> Result<ChatScanResult, String> {
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("Cannot open chat DB: {e}"))?;

    let messages = match platform {
        "WhatsApp" => parse_whatsapp(&conn)?,
        "Telegram" => parse_telegram(&conn)?,
        "Signal" => parse_signal(&conn)?,
        _ => parse_generic_messages(&conn, platform)?,
    };

    let message_count = messages.len();
    Ok(ChatScanResult {
        platform: platform.into(),
        db_path: db_path.into(),
        message_count,
        messages,
    })
}

fn parse_whatsapp(conn: &rusqlite::Connection) -> Result<Vec<ChatMessage>, String> {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .map_err(|e| e.to_string())?
        .query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();

    if tables.iter().any(|t| t == "messages") {
        let sql = "SELECT key_remote_jid, remote_resource, data, timestamp, media_wa_type \
                   FROM messages ORDER BY timestamp DESC LIMIT 100";
        return query_chat(conn, "WhatsApp", sql, |row| {
            let jid: String = row.get(0).unwrap_or_default();
            let sender: String = row.get(1).unwrap_or_else(|_| jid.clone());
            let body: String = row.get(2).unwrap_or_default();
            let ts: i64 = row.get(3).unwrap_or(0);
            let mtype: i64 = row.get(4).unwrap_or(0);
            (jid, sender, body, ts, format!("type_{mtype}"))
        });
    }

    parse_generic_messages(conn, "WhatsApp")
}

fn parse_telegram(conn: &rusqlite::Connection) -> Result<Vec<ChatMessage>, String> {
    for (sql, platform) in [
        (
            "SELECT uid, out, message, date, media FROM messages ORDER BY date DESC LIMIT 100",
            "Telegram",
        ),
        (
            "SELECT chat_id, user_id, text, date FROM messages_v2 ORDER BY date DESC LIMIT 100",
            "Telegram",
        ),
    ] {
        if let Ok(msgs) = query_chat(conn, platform, sql, |row| {
            let chat: String = row.get(0).map(|v: i64| v.to_string()).unwrap_or_default();
            let sender: String = row
                .get(1)
                .map(|v: i64| if v == 1 { "self".into() } else { v.to_string() })
                .unwrap_or_else(|_| "unknown".into());
            let body: String = row.get(2).unwrap_or_default();
            let ts: i64 = row.get(3).unwrap_or(0);
            (chat, sender, body, ts, "text".into())
        }) {
            if !msgs.is_empty() {
                return Ok(msgs);
            }
        }
    }
    parse_generic_messages(conn, "Telegram")
}

fn parse_signal(conn: &rusqlite::Connection) -> Result<Vec<ChatMessage>, String> {
    let sql = "SELECT thread_id, source, body, date_sent FROM sms ORDER BY date_sent DESC LIMIT 100";
    query_chat(conn, "Signal", sql, |row| {
        let chat: String = row.get(0).map(|v: i64| v.to_string()).unwrap_or_default();
        let sender: String = row.get(1).unwrap_or_else(|_| "unknown".into());
        let body: String = row.get(2).unwrap_or_default();
        let ts: i64 = row.get(3).unwrap_or(0);
        (chat, sender, body, ts, "sms".into())
    })
    .or_else(|_| parse_generic_messages(conn, "Signal"))
}

fn parse_generic_messages(
    conn: &rusqlite::Connection,
    platform: &str,
) -> Result<Vec<ChatMessage>, String> {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .map_err(|e| e.to_string())?
        .query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();

    for table in &tables {
        let cols: Vec<String> = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|e| e.to_string())?
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();

        let msg_col = cols
            .iter()
            .find(|c| {
                let l = c.to_lowercase();
                l.contains("message") || l == "data" || l == "body" || l == "text"
            })
            .cloned();
        let sender_col = cols.iter().find(|c| {
            let l = c.to_lowercase();
            l.contains("sender") || l == "from" || l.contains("remote_resource")
        });
        let ts_col = cols.iter().find(|c| {
            let l = c.to_lowercase();
            l.contains("timestamp") || l == "date" || l.contains("time")
        });

        if let Some(msg_c) = msg_col {
            let sender_c = sender_col.map(|s| s.as_str()).unwrap_or("''");
            let ts_c = ts_col.map(|s| s.as_str()).unwrap_or("0");
            let sql = format!(
                "SELECT {sender_c}, {msg_c}, {ts_c} FROM {table} LIMIT 50"
            );
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(ChatMessage {
                        platform: platform.into(),
                        chat_id: table.clone(),
                        sender: row.get(0).unwrap_or_else(|_| "—".into()),
                        message: row.get(1).unwrap_or_default(),
                        timestamp: format_timestamp(row.get(2).unwrap_or(0i64)),
                        message_type: "text".into(),
                    })
                })
                .map_err(|e| e.to_string())?;
            let msgs: Vec<_> = rows.flatten().collect();
            if !msgs.is_empty() {
                return Ok(msgs);
            }
        }
    }
    Ok(vec![])
}

fn query_chat<F>(conn: &rusqlite::Connection, platform: &str, sql: &str, map: F) -> Result<Vec<ChatMessage>, String>
where
    F: Fn(&rusqlite::Row<'_>) -> (String, String, String, i64, String),
{
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            let (chat, sender, body, ts, mtype) = map(row);
            Ok(ChatMessage {
                platform: platform.into(),
                chat_id: chat,
                sender,
                message: body,
                timestamp: format_timestamp(ts),
                message_type: mtype,
            })
        })
        .map_err(|e| e.to_string())?;
    Ok(rows.flatten().collect())
}

fn format_timestamp(ts: i64) -> String {
    if ts <= 0 {
        return "—".into();
    }
    let secs = if ts > 1_000_000_000_000 {
        ts / 1000
    } else if ts > 1_000_000_000 {
        ts
    } else {
        ts + 946_684_800
    };
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}
