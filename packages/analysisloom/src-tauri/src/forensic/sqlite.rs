//! Read-only SQLite artifact browser for forensic databases.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqliteDbInfo {
    pub path: String,
    pub tables: Vec<String>,
    pub page_count: i64,
    pub page_size: i64,
    pub encoding: String,
    pub schema_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqliteColumn {
    pub name: String,
    pub col_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqliteQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: usize,
    pub sql: String,
}

fn open_readonly(path: &str) -> Result<rusqlite::Connection, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("Database not found: {path}"));
    }
    let head = std::fs::read(path).map_err(|e| format!("Cannot read file: {e}"))?;
    if head.len() < 16 || !head.starts_with(b"SQLite format 3") {
        return Err("Not a SQLite database (missing magic header)".into());
    }
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Cannot open database: {e}"))
}

pub fn db_info(path: &str) -> Result<SqliteDbInfo, String> {
    let conn = open_readonly(path)?;
    let mut tables = vec![];
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|e| e.to_string())?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    for name in names.flatten() {
        tables.push(name);
    }

    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap_or(0);
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap_or(0);
    let encoding: String = conn
        .query_row("PRAGMA encoding", [], |row| row.get(0))
        .unwrap_or_else(|_| "UTF-8".into());
    let schema_version: i64 = conn
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .unwrap_or(0);

    Ok(SqliteDbInfo {
        path: path.to_string(),
        tables,
        page_count,
        page_size,
        encoding,
        schema_version,
    })
}

pub fn table_columns(path: &str, table: &str) -> Result<Vec<SqliteColumn>, String> {
    if !is_safe_identifier(table) {
        return Err("Invalid table name".into());
    }
    let conn = open_readonly(path)?;
    let sql = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let cols = stmt
        .query_map([], |row| {
            Ok(SqliteColumn {
                name: row.get(1)?,
                col_type: row.get(2)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(cols)
}

pub fn query_table(path: &str, table: &str, limit: u32) -> Result<SqliteQueryResult, String> {
    if !is_safe_identifier(table) {
        return Err("Invalid table name".into());
    }
    let limit = limit.clamp(1, 500);
    let conn = open_readonly(path)?;
    let sql = format!(
        "SELECT * FROM \"{}\" LIMIT {}",
        table.replace('"', "\"\""),
        limit
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let col_count = stmt.column_count();
    let columns: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let rows_iter = stmt
        .query_map([], |row| {
            let mut values = vec![];
            for i in 0..col_count {
                values.push(sql_value(row, i)?);
            }
            Ok(values)
        })
        .map_err(|e| e.to_string())?;

    let mut rows = vec![];
    for row in rows_iter.flatten() {
        rows.push(row);
    }
    let row_count = rows.len();

    Ok(SqliteQueryResult {
        columns,
        rows,
        row_count,
        sql,
    })
}

pub fn run_select(path: &str, query: &str, limit: u32) -> Result<SqliteQueryResult, String> {
    let trimmed = query.trim();
    let upper = trimmed.to_uppercase();
    if !upper.starts_with("SELECT") {
        return Err("Only SELECT queries are allowed".into());
    }
    if upper.contains(';') && trimmed.matches(';').count() > 1 {
        return Err("Multiple statements are not allowed".into());
    }
    let limit = limit.clamp(1, 500);
    let sql = if upper.contains("LIMIT") {
        trimmed.trim_end_matches(';').to_string()
    } else {
        format!("{} LIMIT {}", trimmed.trim_end_matches(';'), limit)
    };

    let conn = open_readonly(path)?;
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let col_count = stmt.column_count();
    let columns: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let rows_iter = stmt
        .query_map([], |row| {
            let mut values = vec![];
            for i in 0..col_count {
                values.push(sql_value(row, i)?);
            }
            Ok(values)
        })
        .map_err(|e| e.to_string())?;

    let mut rows = vec![];
    for row in rows_iter.flatten() {
        rows.push(row);
    }
    let row_count = rows.len();

    Ok(SqliteQueryResult {
        columns,
        rows,
        row_count,
        sql,
    })
}

fn sql_value(row: &rusqlite::Row<'_>, i: usize) -> Result<serde_json::Value, rusqlite::Error> {
    let val: rusqlite::types::Value = row.get(i)?;
    Ok(match val {
        rusqlite::types::Value::Null => serde_json::Value::Null,
        rusqlite::types::Value::Integer(n) => serde_json::json!(n),
        rusqlite::types::Value::Real(f) => serde_json::json!(f),
        rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
        rusqlite::types::Value::Blob(b) => {
            serde_json::Value::String(format!("<blob {} bytes>", b.len()))
        }
    })
}

fn is_safe_identifier(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_db() -> String {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("analysisloom_test_{stamp}.db"));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, message TEXT);
             INSERT INTO messages (sender, message) VALUES ('+62812', 'Hello!');
             INSERT INTO messages (sender, message) VALUES ('+62813', 'Meeting at 3pm');",
        )
        .unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn sqlite_info_and_query() {
        let path = sample_db();
        let info = db_info(&path).unwrap();
        assert!(info.tables.contains(&"messages".to_string()));
        let result = query_table(&path, "messages", 10).unwrap();
        assert_eq!(result.row_count, 2);
        assert_eq!(result.columns, vec!["id", "sender", "message"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sqlite_rejects_non_select() {
        let path = sample_db();
        assert!(run_select(&path, "DELETE FROM messages", 10).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
