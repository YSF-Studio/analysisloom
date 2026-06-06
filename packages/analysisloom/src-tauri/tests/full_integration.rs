//! End-to-end integration: all Tauri commands against randomly generated fixtures.

use analysisloom_lib::commands::*;
use analysisloom_lib::fixtures_gen;
use analysisloom_lib::forensic::carving;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn setup_db_home(home: &std::path::Path) {
    std::fs::create_dir_all(home).expect("create test home");
    std::env::set_var("HOME", home);
    analysisloom_lib::db::init().expect("db init");
}

#[test]
fn full_forensic_pipeline_with_random_fixtures() {
    let ws = fixtures_gen::generate_workspace(42);
    let home = ws.root.join("home");
    setup_db_home(&home);

    println!("Fixture workspace: {}", ws.root.display());

    // ─── Case management ───
    let case = create_case("Random Forensic Case".into(), "Test Analyst".into()).expect("create_case");
    assert!(!case.id.is_empty());
    let cases = list_cases().expect("list_cases");
    assert!(cases.iter().any(|c| c.id == case.id));
    let fetched = get_case(case.id.clone()).expect("get_case");
    assert_eq!(fetched.name, "Random Forensic Case");

    // ─── NTFS parse ───
    let mft = parse_mft(ws.ntfs_image.to_string_lossy().to_string()).expect("parse_mft");
    assert!(!mft.is_empty(), "MFT should contain entries from synthetic image");
    assert!(mft.iter().any(|e| e.filename.contains("Windows") || e.filename == "."));
    println!("MFT entries: {}", mft.len());

    // ─── Encryption detection ───
    let enc_ntfs = detect_encrypted(ws.ntfs_image.to_string_lossy().to_string()).expect("detect_encrypted ntfs");
    let enc_luks = detect_encrypted(ws.luks_image.to_string_lossy().to_string()).expect("detect_encrypted luks");
    assert!(!enc_luks.is_empty(), "LUKS image should trigger detection");
    println!("Encryption findings: ntfs={}, luks={}", enc_ntfs.len(), enc_luks.len());

    // ─── Hash & preview ───
    let hashes = hash_file(ws.evidence_txt.to_string_lossy().to_string()).expect("hash_file");
    assert!(hashes.sha256.is_some());
    let preview = preview_file(ws.evidence_txt.to_string_lossy().to_string()).expect("preview_file txt");
    assert!(preview.metadata.sha256.is_some());
    let png_preview = preview_file(ws.evidence_png.to_string_lossy().to_string()).expect("preview_file png");
    assert_eq!(png_preview.extension, "png");

    // ─── SQLite browser ───
    let db_info = sqlite_db_info(ws.sqlite_db.to_string_lossy().to_string()).expect("sqlite_db_info");
    assert!(db_info.tables.contains(&"messages".to_string()));
    let cols = sqlite_table_columns(
        ws.sqlite_db.to_string_lossy().to_string(),
        "messages".into(),
    )
    .expect("sqlite_table_columns");
    assert!(!cols.is_empty());
    let rows = sqlite_query_table(
        ws.sqlite_db.to_string_lossy().to_string(),
        "messages".into(),
        Some(10),
    )
    .expect("sqlite_query_table");
    assert_eq!(rows.row_count, 10);
    let custom = sqlite_run_query(
        ws.sqlite_db.to_string_lossy().to_string(),
        "SELECT sender, message FROM messages".into(),
        Some(5),
    )
    .expect("sqlite_run_query");
    assert!(!custom.rows.is_empty());

    // ─── Evidence & timeline ───
    let ev_id = add_evidence(
        case.id.clone(),
        ws.evidence_txt.to_string_lossy().to_string(),
        "text".into(),
        hashes.sha256.clone(),
        Some(preview.metadata.size as i64),
        Some("high".into()),
        Some("Random fixture evidence".into()),
    )
    .expect("add_evidence");
    assert!(ev_id.starts_with("EVD-"));

    record_timeline_event(
        case.id.clone(),
        chrono::Utc::now().to_rfc3339(),
        "NTFS".into(),
        ws.ntfs_image.to_string_lossy().to_string(),
        format!("mft_loaded_{}", mft.len()),
    )
    .expect("record_timeline_event");

    let timeline = get_timeline(case.id.clone()).expect("get_timeline");
    assert!(!timeline.is_empty());

    let search = keyword_search(case.id.clone(), "password".into()).expect("keyword_search");
    assert!(!search.is_empty(), "Should find 'password' in evidence text");

    let stats = case_stats(case.id.clone()).expect("case_stats");
    assert!(stats.evidence_count >= 1);
    assert!(stats.findings_count >= 1);

    let evidence = list_evidence(case.id.clone()).expect("list_evidence");
    assert_eq!(evidence.len(), 1);
    let findings = list_findings(case.id.clone()).expect("list_findings");
    assert!(!findings.is_empty());

    // ─── Bookmarks & audit ───
    let bm_id = add_bookmark(
        case.id.clone(),
        ws.evidence_txt.to_string_lossy().to_string(),
        0,
        Some("suspicious".into()),
        Some("integration test".into()),
    )
    .expect("add_bookmark");
    let bookmarks = list_bookmarks(case.id.clone()).expect("list_bookmarks");
    assert!(!bookmarks.is_empty());
    delete_bookmark(bm_id).expect("delete_bookmark");

    log_action(
        case.id.clone(),
        "INTEGRATION_TEST".into(),
        "full pipeline".into(),
    )
    .expect("log_action");
    let audit = get_audit_log(case.id.clone()).expect("get_audit_log");
    assert!(!audit.is_empty());

    // ─── Carving (sync) ───
    let cancel = AtomicBool::new(false);
    let carve_result = carving::carve_files(
        ws.carve_image.to_string_lossy().as_ref(),
        ws.carve_output.to_string_lossy().as_ref(),
        &cancel,
    )
    .expect("carve_files");
    assert!(carve_result.files_found > 0, "Should carve embedded signatures");
    println!("Carved files: {}", carve_result.files_found);

    // ─── Integrity: hash manifest import & verify ───
    let manifest_path =
        fixtures_gen::write_hash_manifest(&ws.root, &ws.evidence_txt, &ws.evidence_png);
    let import = import_hash_manifest(case.id.clone(), manifest_path.to_string_lossy().to_string())
        .expect("import_hash_manifest");
    assert_eq!(import["fileCount"], 2);
    assert_eq!(import["signatureVerified"], true);

    let verify_ok = verify_evidence_integrity(
        case.id.clone(),
        ws.evidence_txt.to_string_lossy().to_string(),
        hashes.sha256.clone().unwrap(),
    )
    .expect("verify_evidence_integrity ok");
    assert!(verify_ok.verified);
    assert!(verify_ok.expected_sha256.is_some());

    let verify_fail = verify_evidence_integrity(
        case.id.clone(),
        ws.evidence_txt.to_string_lossy().to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000".into(),
    )
    .expect("verify_evidence_integrity fail");
    assert!(!verify_fail.verified);

    let note_id = append_case_note(
        case.id.clone(),
        "Observed password keyword in evidence during integration test".into(),
        Some(ws.evidence_txt.to_string_lossy().to_string()),
    )
    .expect("append_case_note");
    assert!(note_id > 0);
    let notes = list_case_notes(case.id.clone()).expect("list_case_notes");
    assert_eq!(notes.len(), 1);

    let findings_list = list_findings(case.id.clone()).expect("list_findings");
    assert!(!findings_list.is_empty());
    let finding_id = findings_list[0].id;
    review_finding(
        finding_id,
        "approved".into(),
        "Peer Reviewer".into(),
        Some("Confirmed during integration test".into()),
    )
    .expect("review_finding");
    let reviewed = list_findings(case.id.clone()).expect("list_findings reviewed");
    assert_eq!(reviewed[0].review_status.as_deref(), Some("approved"));

    let bm_id = add_bookmark(
        case.id.clone(),
        ws.evidence_txt.to_string_lossy().to_string(),
        0,
        Some("export-test".into()),
        Some("bookmark for export".into()),
    )
    .expect("add_bookmark for export");
    let export_bm_path = ws.root.join("bookmark_export.html");
    export_bookmark(
        case.id.clone(),
        bm_id,
        export_bm_path.to_string_lossy().to_string(),
    )
    .expect("export_bookmark");
    assert!(export_bm_path.exists());

    let export_finding_path = ws.root.join("finding_export.html");
    export_finding(
        case.id.clone(),
        finding_id,
        export_finding_path.to_string_lossy().to_string(),
    )
    .expect("export_finding");
    assert!(export_finding_path.exists());

    let sealed = seal_case(case.id.clone(), "Test Analyst".into()).expect("seal_case");
    assert_eq!(sealed.status, "sealed");
    assert!(sealed.seal_hash.is_some());

    let seal_block = add_evidence(
        case.id.clone(),
        ws.evidence_png.to_string_lossy().to_string(),
        "image".into(),
        None,
        None,
        None,
        None,
    );
    assert!(seal_block.is_err(), "sealed case should block add_evidence");

    // ─── Reports ───
    let html_report = generate_case_report(case.id.clone(), "html".into()).expect("html report");
    assert!(std::path::Path::new(&html_report).exists());
    let html_body = std::fs::read_to_string(&html_report).expect("read html report");
    assert!(html_body.contains("Hash Chain Validation"));
    assert!(html_body.contains("Tool Limitations"));
    assert!(html_body.contains("Analyst Notes"));
    assert!(html_body.contains("Finding Visual Documentation"));
    assert!(html_body.contains("ALL VERIFIED") || html_body.contains("Hash chain intact"));

    let pdf_report = generate_case_report(case.id.clone(), "pdf".into()).expect("pdf report");
    assert!(std::path::Path::new(&pdf_report).exists());

    // ─── About ───
    let about = about_info();
    assert_eq!(about["appName"], "AnalysisLoom");

    // ─── V2: EVTX, macOS, PCAP, bundle export ───
    fixtures_gen::write_v2_extras(&ws.root);

    let evtx = parse_evtx_log(ws.root.join("Security.evtx").to_string_lossy().to_string())
        .expect("parse_evtx_log");
    assert!(!evtx.events.is_empty(), "EVTX should yield security events");
    println!("EVTX events: {}", evtx.events.len());

    let pcap = analyze_pcap(ws.root.join("capture.pcap").to_string_lossy().to_string())
        .expect("analyze_pcap");
    assert!(pcap.packets_parsed > 0, "PCAP should parse packets");
    println!("PCAP flows: {}", pcap.flows.len());

    let macos = scan_macos_artifacts(ws.root.join("macos_profile").to_string_lossy().to_string())
        .expect("scan_macos_artifacts");
    assert!(!macos.is_empty());
    println!("macOS artifact sources: {}", macos.len());

    let bundle_out = ws.root.join("case_bundle.zip");
    let bundle = export_case_bundle(case.id.clone(), bundle_out.to_string_lossy().to_string())
        .expect("export_case_bundle");
    assert!(std::path::Path::new(&bundle.zip_path).exists());
    assert!(bundle.file_count >= 1);
    println!("Bundle files: {}", bundle.file_count);

    // ─── Async carving commands ───
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        start_carving(
            ws.carve_image.to_string_lossy().to_string(),
            ws.carve_output.to_string_lossy().to_string(),
        )
        .await
        .expect("start_carving");

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let p = get_carving_progress().expect("get_carving_progress");
            if p.is_done {
                break;
            }
            if Instant::now() > deadline {
                cancel_carving();
                panic!("async carving timed out");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let async_result = get_carving_result();
        assert!(async_result.is_some());
        assert!(async_result.unwrap().files_found > 0);
    });

    // ─── Cleanup case ───
    delete_case(case.id).expect("delete_case");

    let _ = std::fs::remove_dir_all(&ws.root);
    println!("✅ Full integration pipeline passed");
}
