#!/usr/bin/env node
/**
 * Capture AnalysisLoom screenshots: light theme + real Rust backend on test fixtures.
 */
import { spawn } from "child_process";
import { mkdir, rm } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer";
import { main as startBridge, shutdown as shutdownBridge } from "./screenshot-invoke-server.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(ROOT, "screenshots");
const PKG = join(ROOT, "packages/analysisloom");
const FIXTURES = process.env.FIXTURES_DIR || join(ROOT, "test-fixtures");
const fx = (name) => join(FIXTURES, name);

const VIEWS = [
  { view: "cases", slug: "case-manager", wait: 500 },
  { view: "files", slug: "ntfs-browser", wait: 800 },
  { view: "timeline", slug: "timeline", button: "Load Timeline", wait: 1200 },
  {
    view: "carving",
    slug: "carved-files",
    fill: [{ selector: ".panel input", value: () => fx("carved_out") }],
    button: "Start Carving",
    wait: 5000,
  },
  { view: "sqlite", slug: "sqlite-manager", wait: 1500 },
  { view: "search", slug: "search", wait: 1200 },
  { view: "bookmarks", slug: "key-findings", wait: 800 },
  { view: "encrypted", slug: "encrypted", button: "Scan Image", wait: 1500 },
  {
    view: "registry",
    slug: "registry",
    fill: [{ selector: ".panel .row input", value: () => fx("SYSTEM") }],
    button: "Analyze Hive",
    wait: 1500,
  },
  { view: "yara", slug: "yara-scanner", button: "Scan Evidence", wait: 2000 },
  { view: "antiforensics", slug: "anti-forensics", button: "Scan MFT Image", wait: 2000 },
  {
    view: "browser",
    slug: "browser-artifacts",
    fill: [{ selector: ".panel .row input", value: () => fx("browser_profile") }],
    button: "Scan Browsers",
    wait: 2000,
  },
  { view: "nsrl", slug: "nsrl-lookup", button: "Lookup Selected File", wait: 1200 },
  {
    view: "memory",
    slug: "memory-bridge",
    fill: [{ selector: ".panel .row input", value: () => fx("volatility.json") }],
    button: "Parse JSON",
    wait: 1500,
  },
  { view: "report", slug: "report", wait: 800 },
  { view: "about", slug: "about", wait: 600 },
];

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: "inherit", cwd: opts.cwd || ROOT, env: { ...process.env, ...opts.env } });
    p.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))));
  });
}

function startPreview() {
  return new Promise((resolve, reject) => {
    const proc = spawn("npx", ["vite", "preview", "--host", "127.0.0.1", "--port", "4173"], {
      cwd: PKG,
      stdio: "pipe",
      env: process.env,
    });
    let ready = false;
    const onData = (d) => {
      const s = d.toString();
      if (s.includes("4173") && !ready) {
        ready = true;
        resolve(proc);
      }
    };
    proc.stdout.on("data", onData);
    proc.stderr.on("data", onData);
    proc.on("error", reject);
    setTimeout(() => {
      if (!ready) {
        ready = true;
        resolve(proc);
      }
    }, 8000);
  });
}

async function fillInput(page, selector, value) {
  await page.evaluate(
    ({ selector, value }) => {
      const input = document.querySelector(selector);
      if (!input) return;
      input.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      setter.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    },
    { selector, value }
  );
}

async function clickButton(page, label) {
  await page.evaluate((text) => {
    const btn = Array.from(document.querySelectorAll("button")).find((b) => b.textContent.includes(text));
    btn?.click();
  }, label);
}

async function waitForReady(page) {
  await page.waitForFunction(() => document.title.includes("DEMO READY"), { timeout: 120000 });
}

async function main() {
  await mkdir(OUT, { recursive: true });

  const { server: bridgeHttp } = await startBridge();

  console.log("▶ Building screenshot UI (light theme, real Rust backend)...");
  await run("npm", ["run", "build"], {
    cwd: PKG,
    env: {
      SCREENSHOT: "1",
      SCREENSHOT_REAL: "1",
      FIXTURES_DIR: FIXTURES,
      SCREENSHOT_BRIDGE_URL: "http://127.0.0.1:4174",
    },
  });

  console.log("▶ Starting preview server...");
  const preview = await startPreview();
  await new Promise((r) => setTimeout(r, 2000));

  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--window-size=1400,860"],
    defaultViewport: { width: 1400, height: 860 },
  });

  const page = await browser.newPage();
  await page.evaluateOnNewDocument(() => {
    document.documentElement.classList.add("theme-light");
  });
  await page.goto("http://127.0.0.1:4173/", { waitUntil: "networkidle0", timeout: 60000 });
  await page.waitForFunction(() => window.__goToView, { timeout: 15000 });
  await waitForReady(page);

  await page.evaluate(() => window.__setLightTheme?.());
  await new Promise((r) => setTimeout(r, 400));

  let captured = 0;
  for (const { view, slug, button, fill, wait = 600 } of VIEWS) {
    await page.evaluate((v) => window.__goToView(v), view);
    await new Promise((r) => setTimeout(r, 400));
    if (fill) {
      for (const { selector, value } of fill) {
        await fillInput(page, selector, typeof value === "function" ? value() : value);
      }
    }
    if (button) {
      await clickButton(page, button);
    }
    await new Promise((r) => setTimeout(r, wait));
    const path = join(OUT, `${slug}.png`);
    await page.screenshot({ path, type: "png" });
    console.log(`  📸 ${slug} → screenshots/${slug}.png`);
    captured++;
  }

  await page.evaluate(() => window.__goToView("files"));
  await new Promise((r) => setTimeout(r, 600));
  await page.screenshot({ path: join(OUT, "overview.png"), type: "png" });
  console.log("  📸 overview → screenshots/overview.png");

  await browser.close();
  preview.kill("SIGTERM");
  try {
    await fetch("http://127.0.0.1:4174/invoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: "cancel_carving", args: {} }),
    });
  } catch {
    /* bridge may already be stopping */
  }
  bridgeHttp.close();
  shutdownBridge();

  for (const stale of ["analysis_file_browser", "collection_disk_imaging", "compress", "encrypt", "extract", "inspect"]) {
    await rm(join(OUT, `${stale}.png`), { force: true });
  }

  console.log(`✅ Captured ${captured + 1} light-mode screenshots with real fixture processing`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
