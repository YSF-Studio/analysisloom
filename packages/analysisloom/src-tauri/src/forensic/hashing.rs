use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};

pub const HASH_BUFFER_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSet {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

pub fn multi_hash_buffer(data: &[u8]) -> HashSet {
    HashSet {
        md5: Some(format!("{:x}", Md5::digest(data))),
        sha1: Some(format!("{:x}", Sha1::digest(data))),
        sha256: Some(format!("{:x}", Sha256::digest(data))),
    }
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
