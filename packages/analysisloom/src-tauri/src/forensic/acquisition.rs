//! Cross-platform acquisition analysis — auto-detect Windows/Linux/macOS evidence and orchestrate scans.

use super::{browser, chat, email, evtx, linux, macos, registry, windows_artifacts, yara};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSignal {
    pub platform: String,
    pub score: u32,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformDetection {
    pub root_path: String,
    pub primary_platform: String,
    pub platforms: Vec<PlatformSignal>,
    pub mixed: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleScanSummary {
    pub module: String,
    pub platform: String,
    pub status: String,
    pub item_count: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcquisitionScanResult {
    pub root_path: String,
    pub detection: PlatformDetection,
    pub modules: Vec<ModuleScanSummary>,
    pub findings_recorded: usize,
    pub timeline_events: usize,
    pub duration_ms: u64,
}

struct IndicatorHits {
    windows: u32,
    linux: u32,
    macos: u32,
    windows_indicators: Vec<String>,
    linux_indicators: Vec<String>,
    macos_indicators: Vec<String>,
}

pub fn detect_platform(root: &str) -> Result<PlatformDetection, String> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(format!("Path not found: {}", root_path.display()));
    }

    let hits = collect_indicators(root_path, 0, 7);
    build_detection(root, hits)
}

pub fn scan_acquisition(
    root: &str,
    case_id: Option<&str>,
) -> Result<AcquisitionScanResult, String> {
    let started = Instant::now();
    let detection = detect_platform(root)?;
    let root_path = root.to_string();

    let mut modules = vec![];
    let mut findings_recorded = 0usize;
    let mut timeline_events = 0usize;

    let run_windows = platform_active(&detection, "windows");
    let run_linux = platform_active(&detection, "linux");
    let run_macos = platform_active(&detection, "macos");
    let run_cross = true;

    if run_windows {
        push_module(&mut modules, scan_registry(root), "Registry", "windows");
        push_module(&mut modules, scan_evtx(root), "EVTX", "windows");
        push_module(
            &mut modules,
            scan_windows_artifacts(root),
            "Windows Artifacts",
            "windows",
        );
    }

    if run_linux {
        push_module(
            &mut modules,
            scan_linux(root).map(|r| r.events.len()),
            "Linux Artifacts",
            "linux",
        );
    }

    if run_macos {
        push_module(
            &mut modules,
            scan_macos(root).map(|r| r.iter().map(|s| s.artifacts.len()).sum()),
            "macOS Artifacts",
            "macos",
        );
    }

    if run_cross {
        push_module(
            &mut modules,
            scan_browser(root).map(|r| r.iter().map(|b| b.artifacts.len()).sum()),
            "Browser",
            "cross-platform",
        );
        push_module(
            &mut modules,
            scan_chat(root).map(|r| r.iter().map(|c| c.message_count).sum()),
            "Chat",
            "cross-platform",
        );
        push_module(
            &mut modules,
            scan_email(root).map(|r| r.iter().map(|e| e.message_count).sum()),
            "Email",
            "cross-platform",
        );
        push_module(
            &mut modules,
            scan_yara_sample(root),
            "YARA",
            "cross-platform",
        );
    }

    if let Some(case_id) = case_id {
        crate::forensic::case_guard::ensure_case_mutable(case_id)?;
        for m in &modules {
            if m.status == "ok" && m.item_count > 0 {
                if record_timeline(case_id, &m.module, root, m.item_count).is_ok() {
                    timeline_events += 1;
                }
                if let Some((desc, sev)) = notable_finding(&m.module, m.item_count) {
                    if record_finding(case_id, &desc, root, sev).is_ok() {
                        findings_recorded += 1;
                    }
                }
            }
        }
        let _ = log_scan(case_id, &detection.primary_platform, modules.len());
    }

    Ok(AcquisitionScanResult {
        root_path,
        detection,
        modules,
        findings_recorded,
        timeline_events,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn platform_active(detection: &PlatformDetection, platform: &str) -> bool {
    if detection.primary_platform == platform {
        return true;
    }
    if detection.mixed {
        return detection
            .platforms
            .iter()
            .any(|p| p.platform == platform && p.score >= 2);
    }
    detection.primary_platform == "unknown" || detection.primary_platform == "mixed"
}

fn build_detection(root: &str, hits: IndicatorHits) -> Result<PlatformDetection, String> {
    let platforms = vec![
        PlatformSignal {
            platform: "windows".into(),
            score: hits.windows,
            indicators: hits.windows_indicators,
        },
        PlatformSignal {
            platform: "linux".into(),
            score: hits.linux,
            indicators: hits.linux_indicators,
        },
        PlatformSignal {
            platform: "macos".into(),
            score: hits.macos,
            indicators: hits.macos_indicators,
        },
    ];

    let max_score = platforms.iter().map(|p| p.score).max().unwrap_or(0);
    let active: Vec<_> = platforms.iter().filter(|p| p.score > 0).collect();
    let mixed = active.len() > 1
        && active
            .iter()
            .any(|p| p.score >= max_score.saturating_sub(2));

    let primary_platform = if max_score == 0 {
        "unknown".into()
    } else if mixed {
        "mixed".into()
    } else {
        platforms
            .iter()
            .max_by_key(|p| p.score)
            .map(|p| p.platform.clone())
            .unwrap_or_else(|| "unknown".into())
    };

    let confidence = if max_score == 0 {
        0.0
    } else {
        let top = max_score as f64;
        let total = (hits.windows + hits.linux + hits.macos).max(1) as f64;
        (top / total).min(1.0)
    };

    Ok(PlatformDetection {
        root_path: root.into(),
        primary_platform,
        platforms,
        mixed,
        confidence,
    })
}

fn collect_indicators(dir: &Path, depth: u8, max_depth: u8) -> IndicatorHits {
    let mut hits = IndicatorHits {
        windows: 0,
        linux: 0,
        macos: 0,
        windows_indicators: vec![],
        linux_indicators: vec![],
        macos_indicators: vec![],
    };
    walk_indicators(dir, depth, max_depth, &mut hits);
    hits
}

fn walk_indicators(dir: &Path, depth: u8, max_depth: u8, hits: &mut IndicatorHits) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let lower = name.to_lowercase();
        let full = path.to_string_lossy().to_lowercase();

        score_path(&name, &lower, &full, hits);

        if path.is_dir() {
            walk_indicators(&path, depth + 1, max_depth, hits);
        }
    }
}

fn score_path(name: &str, lower: &str, full: &str, hits: &mut IndicatorHits) {
    let mut add = |platform: &str, indicator: &str| match platform {
        "windows" => {
            hits.windows += 1;
            push_indicator(&mut hits.windows_indicators, indicator);
        }
        "linux" => {
            hits.linux += 1;
            push_indicator(&mut hits.linux_indicators, indicator);
        }
        "macos" => {
            hits.macos += 1;
            push_indicator(&mut hits.macos_indicators, indicator);
        }
        _ => {}
    };

    if lower.ends_with(".pf")
        || lower.ends_with(".evtx")
        || lower.ends_with(".lnk")
        || lower.ends_with("-automaticdestinations-ms")
        || name == "NTUSER.DAT"
        || name == "SYSTEM"
        || name == "SOFTWARE"
        || name == "SAM"
        || full.contains("\\windows\\")
        || full.contains("/windows/")
        || lower == "prefetch"
    {
        add("windows", name);
    }

    if lower.contains("auth.log")
        || lower == "secure"
        || lower.contains("audit.log")
        || lower.contains("syslog")
        || lower == "messages"
        || lower.contains("journal")
        || lower.contains("bash_history")
        || lower == "cron"
        || full.contains("/var/log/")
        || full.contains("var/log/")
        || full.contains("/etc/passwd")
        || full.contains("etc/passwd")
    {
        add("linux", name);
    }

    if lower == "knowledgec.db"
        || lower.ends_with(".logarchive")
        || full.contains("library/preferences")
        || full.contains("library/application support")
        || full.contains("library/logs")
        || (lower.ends_with(".plist") && full.contains("library"))
        || full.contains("lssharedfilelist")
        || lower == "tcc.db"
    {
        add("macos", name);
    }

    if lower == "google" && full.contains("chrome") {
        add("windows", "Chrome profile");
        add("linux", "Chrome profile");
        add("macos", "Chrome profile");
    }
}

fn push_indicator(list: &mut Vec<String>, indicator: &str) {
    if list.len() < 12 && !list.iter().any(|i| i == indicator) {
        list.push(indicator.into());
    }
}

fn push_module(
    modules: &mut Vec<ModuleScanSummary>,
    result: Result<usize, String>,
    module: &str,
    platform: &str,
) {
    match result {
        Ok(count) => modules.push(ModuleScanSummary {
            module: module.into(),
            platform: platform.into(),
            status: "ok".into(),
            item_count: count,
            message: format!("{count} items analyzed"),
        }),
        Err(e) => modules.push(ModuleScanSummary {
            module: module.into(),
            platform: platform.into(),
            status: "error".into(),
            item_count: 0,
            message: e,
        }),
    }
}

fn scan_registry(root: &str) -> Result<usize, String> {
    let hives = find_hives(Path::new(root), 0, 6);
    if hives.is_empty() {
        let results = registry::scan_hives_in_directory(root)?;
        return Ok(results.iter().map(|r| r.findings.len()).sum());
    }
    let mut total = 0usize;
    for hive in hives {
        if let Ok(r) = registry::analyze_hive(hive.to_string_lossy().as_ref()) {
            total += r.findings.len();
        }
    }
    Ok(total)
}

fn find_hives(dir: &Path, depth: u8, max: u8) -> Vec<PathBuf> {
    let mut out = vec![];
    if depth > max {
        return out;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if matches!(
                    name,
                    "SYSTEM" | "SOFTWARE" | "SAM" | "NTUSER.DAT" | "SECURITY"
                ) {
                    out.push(path);
                }
            }
        } else if path.is_dir() {
            out.extend(find_hives(&path, depth + 1, max));
        }
    }
    out
}

fn scan_evtx(root: &str) -> Result<usize, String> {
    let results = evtx::scan_evtx_directory(root)?;
    Ok(results.iter().map(|r| r.events.len()).sum())
}

fn scan_windows_artifacts(root: &str) -> Result<usize, String> {
    Ok(windows_artifacts::scan_windows_artifacts(root)?
        .artifacts
        .len())
}

fn scan_linux(root: &str) -> Result<linux::LinuxScanResult, String> {
    linux::scan_linux_artifacts(root)
}

fn scan_macos(root: &str) -> Result<Vec<macos::MacosScanResult>, String> {
    macos::scan_macos_artifacts(root)
}

fn scan_browser(root: &str) -> Result<Vec<browser::BrowserScanResult>, String> {
    browser::scan_browser_artifacts(root)
}

fn scan_chat(root: &str) -> Result<Vec<chat::ChatScanResult>, String> {
    chat::scan_chat_artifacts(root)
}

fn scan_email(root: &str) -> Result<Vec<email::EmailScanResult>, String> {
    email::scan_email_directory(root)
}

fn scan_yara_sample(root: &str) -> Result<usize, String> {
    let mut paths = vec![];
    collect_scannable_files(Path::new(root), 0, 4, &mut paths, 20);
    if paths.is_empty() {
        return Ok(0);
    }
    let string_paths: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into()).collect();
    Ok(yara::scan_with_optional_rules(&string_paths, None)?.len())
}

fn collect_scannable_files(dir: &Path, depth: u8, max: u8, out: &mut Vec<PathBuf>, limit: usize) {
    if depth > max || out.len() >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= limit {
            break;
        }
        let path = entry.path();
        if path.is_file() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            if size > 0 && size < 5_000_000 {
                out.push(path);
            }
        } else if path.is_dir() {
            collect_scannable_files(&path, depth + 1, max, out, limit);
        }
    }
}

fn notable_finding(module: &str, count: usize) -> Option<(String, &'static str)> {
    if count == 0 {
        return None;
    }
    let severity = if module == "YARA" || module == "Linux Artifacts" {
        "high"
    } else if count > 10 {
        "medium"
    } else {
        "info"
    };
    Some((
        format!("Acquisition scan — {module}: {count} artifacts detected"),
        severity,
    ))
}

fn record_timeline(case_id: &str, module: &str, root: &str, count: usize) -> Result<(), String> {
    crate::db::conn().execute(
        "INSERT INTO timeline_events (case_id, timestamp, source, file_path, event_type) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            case_id,
            chrono::Utc::now().to_rfc3339(),
            format!("Acquisition/{module}"),
            root,
            format!("acquisition_{module}_{count}")
        ],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

fn record_finding(
    case_id: &str,
    description: &str,
    path: &str,
    severity: &str,
) -> Result<(), String> {
    crate::db::conn().execute(
        "INSERT INTO findings (case_id, description, file_path, severity) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![case_id, description, path, severity],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn log_scan(case_id: &str, platform: &str, module_count: usize) -> Result<(), String> {
    crate::db::conn()
        .execute(
            "INSERT INTO audit_log (case_id, action, detail) VALUES (?1, 'ACQUISITION_SCAN', ?2)",
            rusqlite::params![
                case_id,
                format!("platform={platform} modules={module_count}")
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
