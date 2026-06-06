//! Built-in YARA-style scanner with default rules + custom .yar loading.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraMatch {
    pub rule_name: String,
    pub file_path: String,
    pub offset: u64,
    pub matched_string: String,
    pub match_snippet: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub(crate) struct YaraRule {
    name: String,
    strings: Vec<YaraString>,
    severity: String,
}

#[derive(Debug, Clone)]
enum YaraString {
    Text {
        id: String,
        pattern: Vec<u8>,
        nocase: bool,
    },
    Hex {
        id: String,
        pattern: Vec<u8>,
    },
}

pub(crate) fn builtin_rules() -> Vec<YaraRule> {
    vec![
        rule_text(
            "Suspicious_PowerShell",
            "powershell",
            "Invoke-Expression",
            "high",
        ),
        rule_text(
            "Mimikatz_String",
            "mimikatz",
            "sekurlsa::logonpasswords",
            "critical",
        ),
        rule_text(
            "Ransomware_Note",
            "ransom",
            "your files have been encrypted",
            "critical",
        ),
        rule_text("Cobalt_Strike", "beacon", "ReflectiveLoader", "critical"),
        rule_hex("PE_Executable", "pe", &[0x4D, 0x5A], "medium"),
        rule_hex("PNG_Header", "png", &[0x89, 0x50, 0x4E, 0x47], "info"),
        rule_hex("PDF_Header", "pdf", &[0x25, 0x50, 0x44, 0x46], "info"),
        rule_text("Bitcoin_Address", "btc", "1", "medium"), // simplified
        rule_text("Tor_Onion", "tor", ".onion", "medium"),
        rule_text("Base64_Blob", "b64", "AAAA", "low"),
    ]
}

fn rule_text(name: &str, id: &str, text: &str, severity: &str) -> YaraRule {
    YaraRule {
        name: name.into(),
        strings: vec![YaraString::Text {
            id: id.into(),
            pattern: text.as_bytes().to_vec(),
            nocase: true,
        }],
        severity: severity.into(),
    }
}

fn rule_hex(name: &str, id: &str, bytes: &[u8], severity: &str) -> YaraRule {
    YaraRule {
        name: name.into(),
        strings: vec![YaraString::Hex {
            id: id.into(),
            pattern: bytes.to_vec(),
        }],
        severity: severity.into(),
    }
}

pub(crate) fn load_rules_from_file(path: &str) -> Result<Vec<YaraRule>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_yar_content(&content)
}

fn parse_yar_content(content: &str) -> Result<Vec<YaraRule>, String> {
    let mut rules = vec![];
    let mut current_name = String::new();
    let mut strings: Vec<YaraString> = vec![];
    let mut in_strings = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            if !current_name.is_empty() && !strings.is_empty() {
                rules.push(YaraRule {
                    name: current_name.clone(),
                    strings: strings.clone(),
                    severity: "medium".into(),
                });
            }
            current_name = trimmed
                .strip_prefix("rule ")
                .unwrap_or("")
                .split('{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            strings.clear();
            in_strings = false;
        } else if trimmed == "strings:" {
            in_strings = true;
        } else if trimmed == "condition:" {
            in_strings = false;
        } else if in_strings {
            if let Some(s) = parse_yar_string_line(trimmed) {
                strings.push(s);
            }
        }
    }
    if !current_name.is_empty() && !strings.is_empty() {
        rules.push(YaraRule {
            name: current_name,
            strings,
            severity: "medium".into(),
        });
    }
    Ok(rules)
}

fn parse_yar_string_line(line: &str) -> Option<YaraString> {
    // $id = "text" nocase  OR  $id = { FF D8 FF }
    let eq = line.split('=').collect::<Vec<_>>();
    if eq.len() < 2 {
        return None;
    }
    let id = eq[0].trim().trim_start_matches('$').to_string();
    let val = eq[1].trim();
    let nocase = val.contains("nocase");
    if val.starts_with('"') {
        let end = val.rfind('"')?;
        let text = &val[1..end];
        Some(YaraString::Text {
            id,
            pattern: text.as_bytes().to_vec(),
            nocase,
        })
    } else if val.starts_with('{') {
        let end = val.rfind('}')?;
        let hex_part = &val[1..end];
        let bytes = parse_hex_string(hex_part)?;
        Some(YaraString::Hex { id, pattern: bytes })
    } else {
        None
    }
}

fn parse_hex_string(s: &str) -> Option<Vec<u8>> {
    let clean: String = s
        .split_whitespace()
        .filter(|t| *t != "??" && !t.is_empty())
        .collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    let mut out = vec![];
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

pub(crate) fn scan_file(path: &str, rules: &[YaraRule]) -> Result<Vec<YaraMatch>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(scan_bytes(&data, path, rules))
}

pub(crate) fn scan_bytes(data: &[u8], file_path: &str, rules: &[YaraRule]) -> Vec<YaraMatch> {
    let mut matches = vec![];
    for rule in rules {
        for ys in &rule.strings {
            let (pat, nocase) = match ys {
                YaraString::Text {
                    pattern, nocase, ..
                } => (pattern.as_slice(), *nocase),
                YaraString::Hex { pattern, .. } => (pattern.as_slice(), false),
            };
            if pat.is_empty() {
                continue;
            }
            if let Some(off) = find_pattern(data, pat, nocase) {
                let id = match ys {
                    YaraString::Text { id, .. } | YaraString::Hex { id, .. } => id.clone(),
                };
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    file_path: file_path.into(),
                    offset: off as u64,
                    matched_string: id,
                    match_snippet: extract_match_snippet(data, off, pat.len()),
                    severity: rule.severity.clone(),
                });
            }
        }
    }
    matches
}

pub(crate) fn scan_paths(paths: &[String], rules: &[YaraRule]) -> Result<Vec<YaraMatch>, String> {
    let mut all = vec![];
    for path in paths {
        if Path::new(path).is_file() {
            all.extend(scan_file(path, rules)?);
        }
    }
    Ok(all)
}

fn extract_match_snippet(data: &[u8], offset: usize, match_len: usize) -> String {
    const CONTEXT: usize = 48;
    let start = offset.saturating_sub(CONTEXT);
    let end = (offset + match_len + CONTEXT).min(data.len());
    let slice = &data[start..end];
    let mut out = String::new();
    for &b in slice {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            out.push(b as char);
        } else if b == b'\n' || b == b'\r' {
            out.push(' ');
        } else {
            out.push('·');
        }
    }
    if out.len() > 200 {
        format!("{}…", &out[..200])
    } else {
        out
    }
}

fn find_pattern(data: &[u8], pattern: &[u8], nocase: bool) -> Option<usize> {
    if pattern.len() > data.len() {
        return None;
    }
    'outer: for i in 0..=data.len() - pattern.len() {
        for (j, &pb) in pattern.iter().enumerate() {
            let db = data[i + j];
            if nocase {
                if !db.eq_ignore_ascii_case(&pb) {
                    continue 'outer;
                }
            } else if db != pb {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

pub fn scan_with_optional_rules(
    paths: &[String],
    rules_path: Option<&str>,
) -> Result<Vec<YaraMatch>, String> {
    let mut rules = builtin_rules();
    if let Some(rp) = rules_path {
        if !rp.is_empty() {
            rules.extend(load_rules_from_file(rp)?);
        }
    }
    scan_paths(paths, &rules)
}
