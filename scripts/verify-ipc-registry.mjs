#!/usr/bin/env node
/**
 * Verifies every #[tauri::command] in commands.rs is registered in lib.rs generate_handler!.
 */
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const commandsPath = join(root, "packages/analysisloom/src-tauri/src/commands.rs");
const libPath = join(root, "packages/analysisloom/src-tauri/src/lib.rs");

const commandsSrc = readFileSync(commandsPath, "utf8");
const libSrc = readFileSync(libPath, "utf8");

const defined = [];
const cmdRe = /#\[tauri::command\]\s*\n\s*pub(?:\s+async)?\s+fn\s+(\w+)/g;
let m;
while ((m = cmdRe.exec(commandsSrc)) !== null) {
  defined.push(m[1]);
}

const handlerBlock = libSrc.match(/generate_handler!\[([\s\S]*?)\]/)?.[1] ?? "";
const registered = [...handlerBlock.matchAll(/commands::(\w+)/g)].map((x) => x[1]);

const missing = defined.filter((name) => !registered.includes(name));
const extra = registered.filter((name) => !defined.includes(name));

let failed = false;
if (missing.length) {
  console.error("❌ Commands NOT registered in lib.rs generate_handler!:");
  for (const name of missing) console.error(`   - ${name}`);
  failed = true;
}
if (extra.length) {
  console.error("❌ Stale entries in generate_handler! (no #[tauri::command]):");
  for (const name of extra) console.error(`   - ${name}`);
  failed = true;
}

if (failed) {
  console.error(`\nDefined: ${defined.length}, Registered: ${registered.length}`);
  process.exit(1);
}

console.log(`✅ IPC registry OK — ${defined.length} commands registered`);
