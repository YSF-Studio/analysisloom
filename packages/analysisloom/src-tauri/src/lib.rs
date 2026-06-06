use tauri::Manager;

pub mod commands;
pub mod db;
pub mod forensic;
pub mod fixtures_gen;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize database
    db::init().expect("Failed to initialize database");

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
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
            commands::log_action,
            commands::get_audit_log,
            commands::add_bookmark,
            commands::list_bookmarks,
            commands::delete_bookmark,
            commands::about_info,
            commands::demo_fixtures,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AnalysisLoom");
}
