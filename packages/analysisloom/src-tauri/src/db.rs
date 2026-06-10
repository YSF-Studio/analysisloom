use once_cell::sync::Lazy;
use rusqlite::Connection;
use std::sync::Mutex;

static DB: Lazy<Result<Mutex<Connection>, String>> = Lazy::new(|| {
    let db_path = dirs_next()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ysf")
        .join("analysisloom.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create db dir: {e}"))?;
    }
    let conn = Connection::open(&db_path).map_err(|e| format!("Cannot open database: {e}"))?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            operator TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS evidence_items (
            id TEXT PRIMARY KEY,
            case_id TEXT REFERENCES cases(id),
            source_path TEXT,
            type TEXT,
            sha256 TEXT,
            size_bytes INTEGER,
            acquired_at TEXT
        );
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            timestamp TEXT,
            source TEXT,
            file_path TEXT,
            event_type TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            description TEXT,
            file_path TEXT,
            severity TEXT DEFAULT 'info'
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            timestamp TEXT DEFAULT (datetime('now')),
            action TEXT NOT NULL,
            detail TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            file_path TEXT NOT NULL,
            offset INTEGER DEFAULT 0,
            tag TEXT,
            note TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS nsrl_hashes (
            sha256 TEXT PRIMARY KEY,
            file_name TEXT,
            product TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl_hashes(sha256);
        CREATE TABLE IF NOT EXISTS case_manifest (
            case_id TEXT PRIMARY KEY REFERENCES cases(id),
            manifest_json TEXT NOT NULL,
            imported_at TEXT DEFAULT (datetime('now')),
            source TEXT,
            file_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT REFERENCES cases(id),
            timestamp TEXT DEFAULT (datetime('now')),
            body TEXT NOT NULL,
            file_path TEXT
        );
    ",
    )
    .map_err(|e| format!("Schema creation failed: {e}"))?;
    let _ = conn.execute(
        "ALTER TABLE findings ADD COLUMN created_at TEXT DEFAULT (datetime('now'))",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''",
        [],
    );
    let _ = conn.execute("ALTER TABLE cases ADD COLUMN sealed_at TEXT", []);
    let _ = conn.execute("ALTER TABLE cases ADD COLUMN sealed_by TEXT", []);
    let _ = conn.execute("ALTER TABLE cases ADD COLUMN seal_hash TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE case_manifest ADD COLUMN signature_verified INTEGER DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE findings ADD COLUMN review_status TEXT DEFAULT 'pending'",
        [],
    );
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN reviewer TEXT", []);
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN reviewed_at TEXT", []);
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN review_note TEXT", []);
    let _ = conn.execute(
        "INSERT OR IGNORE INTO nsrl_hashes (sha256, file_name, product) VALUES ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'empty', 'Empty File')",
        [],
    );
    Ok(Mutex::new(conn))
});

fn dirs_next() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("USERPROFILE")
                .ok()
                .map(std::path::PathBuf::from)
        })
}

pub fn init() -> Result<(), String> {
    DB.as_ref().map(|_| ()).map_err(|e| e.clone())
}
pub fn conn() -> std::sync::MutexGuard<'static, Connection> {
    match DB.as_ref() {
        Ok(db) => db.lock().unwrap_or_else(|e| e.into_inner()),
        Err(err) => panic!("database failed to initialize: {err}"),
    }
}
