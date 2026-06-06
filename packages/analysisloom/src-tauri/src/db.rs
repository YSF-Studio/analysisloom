use once_cell::sync::Lazy;
use rusqlite::Connection;
use std::sync::Mutex;

static DB: Lazy<Mutex<Connection>> = Lazy::new(|| {
    let db_path = dirs_next()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ysf")
        .join("analysisloom.db");
    let _ = std::fs::create_dir_all(db_path.parent().unwrap());
    let conn = Connection::open(&db_path).expect("Cannot open database");
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
    .expect("Schema creation failed");
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
        "INSERT OR IGNORE INTO nsrl_hashes (sha256, file_name, product) VALUES ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'empty', 'NIST Empty File')",
        [],
    );
    Mutex::new(conn)
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
    let _ = &*DB;
    Ok(())
}
pub fn conn() -> std::sync::MutexGuard<'static, Connection> {
    DB.lock().unwrap()
}
