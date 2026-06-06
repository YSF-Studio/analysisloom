//! Unified search: keyword/regex + hex byte patterns.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub file_path: String,
    pub offset: u64,
    pub context: String,
    pub search_type: String,
}

pub fn hex_search_file(path: &str, hex_pattern: &str) -> Result<Vec<SearchHit>, String> {
    let pattern = parse_hex_pattern(hex_pattern)?;
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(find_hex_in_bytes(&data, &pattern, path))
}

pub fn hex_search_paths(paths: &[String], hex_pattern: &str) -> Result<Vec<SearchHit>, String> {
    let pattern = parse_hex_pattern(hex_pattern)?;
    let mut hits = vec![];
    for path in paths {
        if let Ok(data) = std::fs::read(path) {
            hits.extend(find_hex_in_bytes(&data, &pattern, path));
        }
    }
    Ok(hits)
}

pub fn parse_hex_pattern(input: &str) -> Result<Vec<u8>, String> {
    let clean = input.replace([':', '-', ' '], "").to_uppercase();
    if clean.is_empty() || clean.len() % 2 != 0 {
        return Err("Hex pattern must be even-length (e.g. FF D8 FF or ffd8ff)".into());
    }
    let mut out = vec![];
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| format!("Invalid hex at position {i}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn find_hex_in_bytes(data: &[u8], pattern: &[u8], path: &str) -> Vec<SearchHit> {
    let mut hits = vec![];
    if pattern.is_empty() || pattern.len() > data.len() {
        return hits;
    }
    for i in 0..=data.len() - pattern.len() {
        if data[i..i + pattern.len()] == *pattern {
            let ctx_start = i.saturating_sub(8);
            let ctx_end = (i + pattern.len() + 8).min(data.len());
            let context = data[ctx_start..ctx_end]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            hits.push(SearchHit {
                file_path: path.into(),
                offset: i as u64,
                context,
                search_type: "hex".into(),
            });
            if hits.len() >= 500 {
                break;
            }
        }
    }
    hits
}

pub fn is_hex_query(query: &str) -> bool {
    let q = query.trim();
    q.starts_with("hex:")
        || (q.len() >= 4
            && q.chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_whitespace() || c == ':' || c == '-'))
            && q.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 4
            && !q
                .chars()
                .any(|c| c.is_alphabetic() && !matches!(c, 'A'..='F' | 'a'..='f'))
}

pub fn normalize_hex_query(query: &str) -> String {
    query
        .trim()
        .strip_prefix("hex:")
        .unwrap_or(query.trim())
        .to_string()
}
