#!/usr/bin/env node
/**
 * Simulates a digital forensic examiner workflow against real Rust commands + test fixtures.
 * Usage: node scripts/forensic-examiner-walkthrough.mjs
 */
import { spawn } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync, existsSync } from "fs";
import { main as startBridge, shutdown as shutdownBridge } from "./screenshot-invoke-server.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const FIXTURES = process.env.FIXTURES_DIR || join(ROOT, "test-fixtures");
const fx = (name) => join(FIXTURES, name);

const BRIDGE = "http://127.0.0.1:4174";

async function invoke(cmd, args = {}) {
  const res = await fetch(`${BRIDGE}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, args }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(`${cmd}: ${data.error}`);
  return data.result;
}

function section(title) {
  console.log(`\n━━ ${title} ━━`);
}

function ok(msg) {
  console.log(`  ✓ ${msg}`);
}

function note(msg) {
  console.log(`  → ${msg}`);
}

function warn(msg) {
  console.log(`  ⚠ ${msg}`);
}

async function main() {
  const required = [
    "random_ntfs.dd",
    "messages.db",
    "secret_password_log.txt",
    "SYSTEM",
    "volatility.json",
    "browser_profile",
  ];
  for (const f of required) {
    if (!existsSync(fx(f))) {
      console.error(`Missing fixture: ${fx(f)} — run: npm run test:fixtures`);
      process.exit(1);
    }
  }

  const { server } = await startBridge();
  const report = { steps: [], issues: [], findings: [] };

  try {
    section("1. Case intake — open investigation");
    const examiner = "DF Examiner (walkthrough)";
    const caseInfo = await invoke("create_case", {
      name: "INC-2026-USB-042",
      operator: examiner,
    });
    ok(`Case created: ${caseInfo.name} (${caseInfo.id})`);
    report.steps.push("Created case INC-2026-USB-042");

    section("2. Evidence acquisition — load disk image (NTFS/MFT)");
    const ntfsPath = fx("random_ntfs.dd");
    const mft = await invoke("parse_mft", { imagePath: ntfsPath });
    ok(`Parsed MFT: ${mft.length} entries from random_ntfs.dd`);
    const files = mft.filter((e) => !e.isDirectory).map((e) => e.filename);
    note(`Notable files: ${files.join(", ") || "(none)"}`);
    report.findings.push({ area: "NTFS", detail: `${mft.length} MFT records, files: ${files.join(", ")}` });

    section("3. Chain of custody — hash & add evidence");
    const evidencePath = fx("secret_password_log.txt");
    const hashes = await invoke("hash_file", { path: evidencePath });
    const preview = await invoke("preview_file", { path: evidencePath });
    ok(`SHA-256: ${hashes.sha256?.slice(0, 16)}…`);
    const previewText = typeof preview.preview === "string" ? preview.preview : JSON.stringify(preview.preview ?? "");
    const snippet = previewText.slice(0, 80).replace(/\n/g, " ");
    note(`Preview: "${snippet}…"`);
    const evId = await invoke("add_evidence", {
      caseId: caseInfo.id,
      sourcePath: evidencePath,
      itemType: "text",
      sha256: hashes.sha256,
      sizeBytes: preview.metadata?.size,
      tag: "high",
      note: "Password keyword log from suspect USB image",
    });
    ok(`Evidence registered: ${evId}`);
    report.steps.push(`Evidence ${evId} hashed and logged`);

    section("4. Keyword search — hunt for credentials");
    const hits = await invoke("keyword_search", { caseId: caseInfo.id, query: "password" });
    ok(`Keyword "password": ${hits.length} hit(s)`);
    for (const h of hits.slice(0, 3)) {
      note(`${h.filePath} @ offset ${h.offset}: ${(h.context || "").slice(0, 60)}…`);
    }
    report.findings.push({ area: "Search", detail: `${hits.length} password keyword hits` });

    section("5. SQLite analysis — chat/message database");
    const dbPath = fx("messages.db");
    const dbInfo = await invoke("sqlite_db_info", { path: dbPath });
    ok(`Database: ${dbInfo.tables?.join(", ")} (${dbInfo.pageCount} pages)`);
    const rows = await invoke("sqlite_query_table", { path: dbPath, table: "messages", limit: 5 });
    for (const row of rows.rows || []) {
      note(`Message: ${row[1]} → "${(row[2] || "").slice(0, 50)}…"`);
    }
    report.findings.push({ area: "SQLite", detail: `${rows.rowCount} messages in messages.db` });

    section("6. Encryption scan — look for protected volumes");
    const encNtfs = await invoke("detect_encrypted", { imagePath: ntfsPath });
    const encLuks = await invoke("detect_encrypted", { imagePath: fx("luks_volume.dd") });
    ok(`NTFS image: ${encNtfs.length} indicator(s)`);
    ok(`LUKS volume: ${encLuks.length} indicator(s)`);
    for (const e of encLuks.slice(0, 2)) {
      note(`${e.detectionType} @ ${e.location} (confidence ${(e.confidence * 100).toFixed(0)}%)`);
    }
    report.findings.push({ area: "Encryption", detail: `LUKS: ${encLuks.length}, NTFS entropy: ${encNtfs.length}` });

    section("7. Registry analysis — USB & execution artifacts");
    const reg = await invoke("analyze_registry_hive", { path: fx("SYSTEM") });
    ok(`Registry hive SYSTEM: ${reg.findings?.length || 0} forensic keys`);
    for (const f of (reg.findings || []).slice(0, 3)) {
      note(`${f.forensicRelevance}: ${f.keyPath}`);
    }
    report.findings.push({ area: "Registry", detail: `${reg.findings?.length || 0} keys (USB, UserAssist, MRU)` });

    section("8. YARA scan — malware / IOC detection");
    const yara = await invoke("yara_scan_paths", { paths: [evidencePath], rulesPath: null });
    const ruleCount = await invoke("yara_builtin_rule_count");
    ok(`Built-in rules: ${ruleCount}`);
    ok(`YARA matches: ${yara.length}`);
    for (const m of yara) {
      note(`[${m.severity}] ${m.ruleName} in ${m.filePath.split("/").pop()}`);
      report.findings.push({ area: "YARA", detail: `${m.ruleName} (${m.severity})` });
    }

    section("9. Anti-forensics — timestomp & ADS");
    const af = await invoke("analyze_antiforensics_mft", { imagePath: ntfsPath });
    ok(`Anti-forensics indicators: ${af.length}`);
    for (const a of af.slice(0, 3)) {
      note(`[${a.severity}] ${a.detectionType}: ${a.details}`);
    }

    section("10. Browser artifacts — web activity");
    const browser = await invoke("scan_browser_artifacts", { root: fx("browser_profile") });
    const visits = browser.flatMap((b) => b.artifacts || []);
    ok(`Browser artifacts: ${visits.length} entries`);
    for (const v of visits.slice(0, 2)) {
      note(`${v.browser} ${v.artifactType}: ${v.url || v.title}`);
    }

    section("11. Memory bridge — Volatility import");
    const mem = await invoke("parse_volatility_json", { path: fx("volatility.json") });
    ok(`Processes: ${mem.processes?.length || 0}, connections: ${mem.connections?.length || 0}`);
    for (const p of (mem.processes || []).slice(0, 2)) {
      note(`PID ${p.pid}: ${p.name}`);
    }

    section("12. Timeline & bookmarks — investigation journal");
    await invoke("record_timeline_event", {
      caseId: caseInfo.id,
      timestamp: new Date().toISOString(),
      source: "Examiner",
      filePath: evidencePath,
      eventType: "manual_review_complete",
    });
    await invoke("add_bookmark", {
      caseId: caseInfo.id,
      filePath: evidencePath,
      offset: 0,
      tag: "credential-leak",
      note: "Password string in plaintext log — priority finding",
    });
    const timeline = await invoke("get_timeline", { caseId: caseInfo.id });
    const bookmarks = await invoke("list_bookmarks", { caseId: caseInfo.id });
    ok(`Timeline events: ${timeline.length}`);
    ok(`Bookmarks: ${bookmarks.length}`);

    section("13. Cross-platform acquisition — one-click sweep");
    const acq = await invoke("scan_acquisition", { root: FIXTURES, caseId: caseInfo.id });
    const okMods = (acq.modules || []).filter((m) => m.status === "ok" && m.itemCount > 0);
    ok(`Acquisition modules OK: ${okMods.length}/${acq.modules?.length || 0}`);
    for (const m of okMods.slice(0, 5)) {
      note(`${m.moduleId}: ${m.itemCount} items — ${m.summary || ""}`);
    }

    section("14. Report generation — close investigation");
    const htmlPath = await invoke("generate_case_report", { caseId: caseInfo.id, format: "html" });
    ok(`HTML report: ${htmlPath}`);
    if (existsSync(htmlPath)) {
      const body = readFileSync(htmlPath, "utf8");
      const hasHashChain = body.includes("Hash Chain") || body.includes("hash chain");
      const hasFindings = body.includes("Finding") || body.includes("finding");
      note(`Report sections: hash chain=${hasHashChain}, findings=${hasFindings}`);
    }
    const stats = await invoke("case_stats", { caseId: caseInfo.id });
    ok(`Case stats — evidence: ${stats.evidenceCount}, findings: ${stats.findingsCount}, timeline: ${stats.timelineCount}`);

    section("SUMMARY — Examiner assessment");
    console.log(`  Case:        ${caseInfo.name}`);
    console.log(`  Evidence:    ${stats.evidenceCount} item(s)`);
    console.log(`  Findings:    ${stats.findingsCount}`);
    console.log(`  YARA hits:   ${yara.length}`);
    console.log(`  Timeline:    ${stats.timelineCount} events`);
    console.log(`  Modules OK:  ${okMods.length} acquisition modules`);
    console.log("\n✅ Forensic walkthrough completed — all examiner steps succeeded.");
  } catch (e) {
    console.error(`\n❌ Walkthrough failed: ${e.message}`);
    report.issues.push(e.message);
    process.exitCode = 1;
  } finally {
    server.close();
    shutdownBridge();
  }
}

main();
