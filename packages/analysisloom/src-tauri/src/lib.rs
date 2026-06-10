use tauri::Manager;

pub mod commands;
pub mod db;
pub mod fixtures_gen;
pub mod forensic;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize database
    if let Err(err) = db::init() {
        eprintln!("Failed to initialize database: {err}");
        return;
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let Some(window) = app.get_webview_window("main") else {
                return Err("main window not found".into());
            };
            window.set_title("AnalysisLoom — Forensic Analysis Workstation")?;

            // ─── Inject error handler for debugging ───
            let _ = window.eval(
                "window.onerror=function(m,u,l){console.error('FATAL:',m,u,l);};\
                 window.addEventListener('unhandledrejection',function(e){console.error('UNHANDLED:',e.reason);});"
            );

            // ─── GUI Screenshot Mode (set ANALYSISLOOM_FIXTURES_DIR for demo data) ───
            if std::env::var("ANALYSISLOOM_SCREENSHOT").is_ok() {
                let w = window.clone();
                std::thread::spawn(move || {
                    use std::time::Duration;

                    // Wait for frontend demo bootstrap (fixtures + case + MFT)
                    for _ in 0..60 {
                        std::thread::sleep(Duration::from_secs(1));
                        if let Ok(title) = w.title() {
                            if title.contains("DEMO READY") {
                                break;
                            }
                        }
                    }

                    let views: [(&str, &str, &str, u64); 10] = [
                        ("case-manager", "Case Manager", "", 3),
                        ("ntfs-browser", "NTFS Browser", "", 3),
                        (
                            "timeline",
                            "Timeline",
                            "Array.from(document.querySelectorAll('.btn-primary')).find(b=>b.textContent.includes('Load Timeline'))?.click();",
                            2,
                        ),
                        (
                            "carved-files",
                            "Carved Files",
                            "Array.from(document.querySelectorAll('.btn-primary')).find(b=>b.textContent.includes('Start Carving'))?.click();",
                            8,
                        ),
                        ("sqlite-manager", "SQLite Manager", "", 4),
                        ("search", "Search", "", 3),
                        ("key-findings", "Key Findings", "", 3),
                        (
                            "encrypted",
                            "Encrypted",
                            "Array.from(document.querySelectorAll('.btn-primary')).find(b=>b.textContent.includes('Scan'))?.click();",
                            5,
                        ),
                        ("report", "Report", "", 3),
                        ("about", "About", "", 3),
                    ];

                    for (slug, label, action, wait_secs) in views {
                        let nav = format!(
                            "Array.from(document.querySelectorAll('.nav-item')).find(b=>b.textContent.includes('{}'))?.click();",
                            label
                        );
                        let _ = w.eval(&nav);
                        std::thread::sleep(Duration::from_millis(800));
                        if !action.is_empty() {
                            let _ = w.eval(action);
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        let _ = w.set_title(&format!("AnalysisLoom — SCREENSHOT:{slug}"));
                        std::thread::sleep(Duration::from_secs(wait_secs));
                    }

                    let _ = w.set_title("AnalysisLoom — SCREENSHOT:DONE");
                    eprintln!("[SCREENSHOT] All views captured");
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_cases,
            commands::create_case,
            commands::get_case,
            commands::delete_case,
            commands::parse_mft,
            commands::start_carving,
            commands::get_carving_progress,
            commands::cancel_carving,
            commands::get_carving_result,
            commands::add_evidence,
            commands::list_evidence,
            commands::list_findings,
            commands::case_stats,
            commands::record_timeline_event,
            commands::get_timeline,
            commands::keyword_search,
            commands::preview_file,
            commands::hash_file,
            commands::sqlite_db_info,
            commands::sqlite_table_columns,
            commands::sqlite_query_table,
            commands::sqlite_run_query,
            commands::detect_encrypted,
            commands::generate_case_report,
            commands::import_hash_manifest,
            commands::get_case_manifest,
            commands::verify_evidence_integrity,
            commands::append_case_note,
            commands::list_case_notes,
            commands::seal_case,
            commands::review_finding,
            commands::export_bookmark,
            commands::export_finding,
            commands::log_action,
            commands::get_audit_log,
            commands::add_bookmark,
            commands::list_bookmarks,
            commands::delete_bookmark,
            commands::about_info,
            commands::demo_fixtures,
            commands::unified_search,
            commands::hex_search,
            commands::analyze_registry_hive,
            commands::scan_registry_directory,
            commands::yara_scan_paths,
            commands::yara_builtin_rule_count,
            commands::analyze_antiforensics_mft,
            commands::analyze_antiforensics_files,
            commands::scan_browser_artifacts,
            commands::analyze_browser_db,
            commands::nsrl_lookup_file,
            commands::nsrl_lookup_hash,
            commands::nsrl_import,
            commands::nsrl_seed_builtin,
            commands::nsrl_stats,
            commands::parse_volatility_json,
            commands::get_super_timeline,
            commands::list_deleted_mft,
            commands::recover_deleted_carve,
            commands::parse_evtx_log,
            commands::scan_evtx_directory,
            commands::scan_macos_artifacts,
            commands::analyze_macos_plist,
            commands::analyze_pcap,
            commands::scan_windows_artifacts,
            commands::scan_steganography,
            commands::analyze_steganography,
            commands::scan_email_directory,
            commands::scan_chat_artifacts,
            commands::scan_linux_artifacts,
            commands::detect_evidence_platform,
            commands::scan_acquisition,
            commands::list_forensic_plugins,
            commands::run_forensic_plugin,
            commands::export_case_bundle,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("error while running AnalysisLoom: {e}");
        });
}
