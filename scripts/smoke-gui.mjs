#!/usr/bin/env node
/**
 * GUI smoke test — validates production build artifacts and view registry.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const dist = join(root, "packages/analysisloom/dist");
const src = join(root, "packages/analysisloom/src");

let errors = 0;
function fail(msg) {
  console.error(`❌ ${msg}`);
  errors++;
}
function ok(msg) {
  console.log(`✅ ${msg}`);
}

// 1. Production build exists
if (!existsSync(join(dist, "index.html"))) {
  fail("dist/index.html missing — run npm run build:analysisloom");
} else {
  ok("dist/index.html exists");
}

const assets = join(dist, "assets");
if (!existsSync(assets)) {
  fail("dist/assets/ missing");
} else {
  const files = readdirSync(assets);
  const js = files.find((f) => f.endsWith(".js"));
  const css = files.find((f) => f.endsWith(".css"));
  if (!js) fail("No JS bundle in dist/assets");
  else ok(`JS bundle: ${js} (${statSync(join(assets, js)).size} bytes)`);
  if (!css) fail("No CSS bundle in dist/assets");
  else ok(`CSS bundle: ${css} (${statSync(join(assets, css)).size} bytes)`);

  if (js) {
    const bundle = readFileSync(join(assets, js), "utf8");
    const required = [
      "NTFS Browser",
      "SQLite Manager",
      "Encrypted",
      "Inspector",
      "Add to Evidence",
      "parse_mft",
      "detect_encrypted",
      "hash_file",
      "sqlite_db_info",
      "add_evidence",
      "analyze_registry_hive",
      "yara_scan_paths",
      "analyze_antiforensics_mft",
      "scan_browser_artifacts",
      "nsrl_lookup_file",
      "parse_volatility_json",
      "get_super_timeline",
      "unified_search",
    ];
    for (const needle of required) {
      if (!bundle.includes(needle)) {
        fail(`Bundle missing UI/API string: ${needle}`);
      }
    }
    if (errors === 0 || required.every((n) => bundle.includes(n))) {
      ok("Bundle contains all required UI strings and Tauri invoke targets");
    }
  }
}

// 2. View registry completeness
const registryPath = join(src, "lib/viewRegistry.js");
if (!existsSync(registryPath)) {
  fail("viewRegistry.js missing");
} else {
  const mod = await import(registryPath);
  const expected = [
    "cases", "files", "timeline", "carving", "sqlite",
    "search", "bookmarks", "encrypted", "registry", "yara",
    "antiforensics", "browser", "nsrl", "memory", "report", "about",
  ];
  for (const id of expected) {
    if (!mod.VIEW_META[id]) fail(`VIEW_META missing: ${id}`);
  }
  if (mod.DEFAULT_TABS?.[0]?.id === "files") {
    ok(`VIEW_META complete (${expected.length} views)`);
  } else {
    fail("DEFAULT_TABS should pin NTFS Browser");
  }
}

// 3. Logo & theme
for (const f of ["public/logo.svg", "public/shared/theme.css"]) {
  if (!existsSync(join(root, "packages/analysisloom", f))) {
    fail(`Missing ${f}`);
  } else {
    ok(`${f} present`);
  }
}

if (errors > 0) {
  console.error(`\n${errors} GUI smoke check(s) failed`);
  process.exit(1);
}
console.log("\n✅ GUI smoke tests passed");
