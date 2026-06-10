use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

pub const HASH_BUFFER_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSet {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

pub fn multi_hash_buffer(data: &[u8]) -> HashSet {
    HashSet {
        md5: Some(hex_encode(&Md5::digest(data))),
        sha1: Some(hex_encode(&Sha1::digest(data))),
        sha256: Some(hex_encode(&Sha256::digest(data))),
    }
}

/// Stream-hash a file on disk (forensic chain-of-custody).
pub fn multi_hash_file(path: &str) -> Result<HashSet, String> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Cannot open file for hashing: {e}"))?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = [0u8; HASH_BUFFER_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Read error during hashing: {e}"))?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
    }

    Ok(HashSet {
        md5: Some(hex_encode(&md5.finalize())),
        sha1: Some(hex_encode(&sha1.finalize())),
        sha256: Some(hex_encode(&sha256.finalize())),
    })
}

/// Helper function to convert digest output to hex string
fn hex_encode(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub const MAGIC_DB: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"\x25PDF", "PDF"),
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"SQLite format 3", "SQLite"),
];

pub fn check_magic_bytes(data: &[u8]) -> Option<String> {
    for (magic, name) in MAGIC_DB {
        if data.len() >= magic.len() && data.starts_with(magic) {
            return Some((*name).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_file_streams_bytes() {
        let path = std::env::temp_dir().join("analysisloom_hash_test.bin");
        let data = b"forensic chain of custody";
        std::fs::write(&path, data)
            .unwrap_or_else(|e| panic!("write temp hash file: {e}"));
        let hashes = multi_hash_file(
            path.to_str().unwrap_or_else(|| panic!("temp path utf-8")),
        )
        .unwrap_or_else(|e| panic!("hash temp file: {e}"));
        let mem = multi_hash_buffer(data);
        assert_eq!(hashes.sha256, mem.sha256);
        let _ = std::fs::remove_file(&path);
    }
}
