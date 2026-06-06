import {
  DEMO_CASE,
  DEMO_MFT,
  DEMO_HASHES,
  DEMO_TIMELINE,
  DEMO_BOOKMARKS,
  DEMO_SEARCH,
  DEMO_ENCRYPTED,
  DEMO_CARVED,
  DEMO_SQLITE_INFO,
  DEMO_SQLITE_COLUMNS,
  DEMO_SQLITE_ROWS,
  DEMO_AUDIT,
  DEMO_ABOUT,
  DEMO_IMAGE,
} from "./mockData.js";

let carvingDone = false;

export async function invoke(cmd, args = {}) {
  switch (cmd) {
    case "demo_fixtures":
      return null;
    case "list_cases":
      return [DEMO_CASE];
    case "create_case":
      return { ...DEMO_CASE, name: args.name || DEMO_CASE.name, operator: args.operator || "Analyst" };
    case "get_case":
      return DEMO_CASE;
    case "delete_case":
      return;
    case "parse_mft":
      return DEMO_MFT;
    case "hash_file":
      return DEMO_HASHES;
    case "preview_file":
      return {
        extension: (args.path || "").split(".").pop() || "txt",
        metadata: { size: 475, sha256: DEMO_HASHES.sha256, mimeType: "text/plain" },
        preview: "CONFIDENTIAL forensic export\nuser password=RandomP@ss123!",
      };
    case "sqlite_db_info":
      return DEMO_SQLITE_INFO;
    case "sqlite_table_columns":
      return DEMO_SQLITE_COLUMNS[args.table] || [];
    case "sqlite_query_table":
      return DEMO_SQLITE_ROWS[args.table] || { columns: [], rows: [], rowCount: 0 };
    case "sqlite_run_query":
      return DEMO_SQLITE_ROWS.messages;
    case "detect_encrypted":
      return DEMO_ENCRYPTED;
    case "add_evidence":
      return "EVD-DEMO001";
    case "list_evidence":
      return [{ id: "EVD-DEMO001", caseId: DEMO_CASE.id, sourcePath: args.path || "", itemType: "text", sha256: DEMO_HASHES.sha256, sizeBytes: 475, acquiredAt: "2026-06-06" }];
    case "list_findings":
      return [{ id: 1, description: "Password keyword in evidence", filePath: "/workspace/test-fixtures/secret_password_log.txt", severity: "high" }];
    case "case_stats":
      return { evidenceCount: 1, findingsCount: 1, bookmarkCount: 1, timelineCount: 3 };
    case "record_timeline_event":
    case "log_action":
      return;
    case "get_timeline":
      return DEMO_TIMELINE;
    case "keyword_search":
      return DEMO_SEARCH;
    case "add_bookmark":
      return 1;
    case "list_bookmarks":
      return DEMO_BOOKMARKS;
    case "delete_bookmark":
      return;
    case "get_audit_log":
      return DEMO_AUDIT;
    case "generate_case_report":
      return "/tmp/demo-report.html";
    case "about_info":
      return DEMO_ABOUT;
    case "start_carving":
      carvingDone = false;
      setTimeout(() => { carvingDone = true; }, 800);
      return;
    case "get_carving_progress":
      return { percent: carvingDone ? 100 : 45, status: carvingDone ? "Complete" : "Scanning…", isDone: carvingDone };
    case "cancel_carving":
      return;
    case "get_carving_result":
      return { filesFound: DEMO_CARVED.length, files: DEMO_CARVED, bytesScanned: 262144 };
    default:
      console.warn(`[mock] unhandled invoke: ${cmd}`, args);
      return null;
  }
}

export { DEMO_IMAGE };
