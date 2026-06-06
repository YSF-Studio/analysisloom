#!/usr/bin/env node
/**
 * Ensures every invoke('cmd') in frontend has a handler in tauriMock.js (E2E/Playwright).
 */
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = join(root, "packages/analysisloom/src");
const mockPath = join(srcDir, "lib/demo/tauriMock.js");

const mockSrc = readFileSync(mockPath, "utf8");
const mockCommands = new Set([...mockSrc.matchAll(/case\s+["'](\w+)["']/g)].map((m) => m[1]));

const invokeRe = /invoke\(\s*["'](\w+)["']/g;
const used = new Set();

function scanFile(path) {
  const text = readFileSync(path, "utf8");
  let m;
  while ((m = invokeRe.exec(text)) !== null) {
    if (!path.includes("tauriMock.js") && !path.includes("tauriBridgeMock.js")) {
      used.add(m[1]);
    }
  }
}

import { readdirSync, statSync } from "fs";

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(svelte|js|ts)$/.test(name)) scanFile(p);
  }
}
walk(srcDir);

const missing = [...used].filter((cmd) => !mockCommands.has(cmd)).sort();

if (missing.length) {
  console.error("❌ invoke() commands missing from tauriMock.js:");
  for (const cmd of missing) console.error(`   - ${cmd}`);
  process.exit(1);
}

console.log(`✅ Mock coverage OK — ${used.size} invoke targets, ${mockCommands.size} mock handlers`);
