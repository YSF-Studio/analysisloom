//! NSRL-style hash lookup.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NsrlLookupResult {
    pub sha256: String,
    pub known_good: bool,
    pub file_name: Option<String>,
    pub product: Option<String>,
}

pub fn ensure_nsrl_table(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS nsrl_hashes (
            sha256 TEXT PRIMARY KEY,
            file_name TEXT,
            product TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl_hashes(sha256);",
    )
    .map_err(|e| e.to_string())
}

pub fn import_nsrl_file(path: &str) -> Result<usize, String> {
    let db = crate::db::conn();
    ensure_nsrl_table(&db)?;
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut count = 0usize;
    let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let sha256 = parts[0].trim().to_lowercase();
            if sha256.len() == 64 {
                let file_name = parts.get(1).unwrap_or(&"").trim();
                let product = parts.get(2).unwrap_or(&"").trim();
                tx.execute(
                    "INSERT OR IGNORE INTO nsrl_hashes (sha256, file_name, product) VALUES (?1, ?2, ?3)",
                    rusqlite::params![sha256, file_name, product],
                )
                .ok();
                count += 1;
            }
        } else if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
            tx.execute(
                "INSERT OR IGNORE INTO nsrl_hashes (sha256, file_name, product) VALUES (?1, '', 'NSRL')",
                [line.trim().to_lowercase()],
            )
            .ok();
            count += 1;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(count)
}

pub fn seed_builtin_nsrl() -> Result<usize, String> {
    let db = crate::db::conn();
    ensure_nsrl_table(&db)?;
    let known: &[(&str, &str, &str)] = &[
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty",
                "Empty File",
        ),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            "empty-md5",
                "Empty MD5",
        ),
        (
            "5d41402abc4b2a76b9719d911017c592",
            "hello-md5",
                "Sample",
        ),
    ];
    let mut n = 0;
    for (sha, name, product) in known {
        db.execute(
            "INSERT OR IGNORE INTO nsrl_hashes (sha256, file_name, product) VALUES (?1, ?2, ?3)",
            rusqlite::params![sha, name, product],
        )
        .ok();
        n += 1;
    }
    Ok(n)
}

pub fn lookup_sha256(sha256: &str) -> Result<NsrlLookupResult, String> {
    let db = crate::db::conn();
    ensure_nsrl_table(&db)?;
    let hash = sha256.trim().to_lowercase();
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT file_name, product FROM nsrl_hashes WHERE sha256 = ?1",
            [&hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    if let Some((file_name, product)) = row {
        Ok(NsrlLookupResult {
            sha256: hash,
            known_good: true,
            file_name: Some(file_name),
            product: Some(product),
        })
    } else {
        Ok(NsrlLookupResult {
            sha256: hash,
            known_good: false,
            file_name: None,
            product: None,
        })
    }
}

pub fn lookup_file(path: &str) -> Result<NsrlLookupResult, String> {
    let hashes = super::hashing::multi_hash_file(path)?;
    let sha = hashes.sha256.ok_or("Could not compute SHA-256")?;
    lookup_sha256(&sha)
}

pub fn nsrl_stats() -> Result<serde_json::Value, String> {
    let db = crate::db::conn();
    ensure_nsrl_table(&db)?;
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM nsrl_hashes", [], |r| r.get(0))
        .unwrap_or(0);
    Ok(serde_json::json!({ "hashCount": count }))
}
