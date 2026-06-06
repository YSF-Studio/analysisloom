#!/usr/bin/env node
/**
 * Capture AnalysisLoom screenshots via Chrome headless + screenshot build (mocked Tauri).
 */
import { spawn } from "child_process";
import { mkdir, rm } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(ROOT, "screenshots");
const PKG = join(ROOT, "packages/analysisloom");

const VIEWS = [
  { view: "cases", slug: "case-manager" },
  { view: "files", slug: "ntfs-browser" },
  { view: "timeline", slug: "timeline", button: "Load Timeline", wait: 600 },
  { view: "carving", slug: "carved-files", button: "Start Carving", wait: 2500 },
  { view: "sqlite", slug: "sqlite-manager", wait: 800 },
  { view: "search", slug: "search", wait: 600 },
  { view: "bookmarks", slug: "key-findings", wait: 500 },
  { view: "encrypted", slug: "encrypted", button: "Scan Image", wait: 600 },
  { view: "report", slug: "report", wait: 500 },
  { view: "about", slug: "about", wait: 400 },
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
    proc.stdout.on("data", (d) => {
      const s = d.toString();
      if (s.includes("4173") && !ready) {
        ready = true;
        resolve(proc);
      }
    });
    proc.stderr.on("data", (d) => {
      const s = d.toString();
      if (s.includes("4173") && !ready) {
        ready = true;
        resolve(proc);
      }
    });
    proc.on("error", reject);
    setTimeout(() => {
      if (!ready) {
        ready = true;
        resolve(proc);
      }
    }, 8000);
  });
}

async function main() {
  await mkdir(OUT, { recursive: true });

  console.log("▶ Building screenshot UI (mocked Tauri)...");
  await run("npm", ["run", "build"], { cwd: PKG, env: { SCREENSHOT: "1" } });

  console.log("▶ Starting preview server...");
  const preview = await startPreview();
  await new Promise((r) => setTimeout(r, 1500));

  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--window-size=1400,860"],
    defaultViewport: { width: 1400, height: 860 },
  });

  const page = await browser.newPage();
  await page.goto("http://127.0.0.1:4173/", { waitUntil: "networkidle0", timeout: 30000 });
  await page.waitForFunction(() => window.__goToView, { timeout: 10000 });

  let captured = 0;
  for (const { view, slug, button, wait = 400 } of VIEWS) {
    await page.evaluate((v) => window.__goToView(v), view);
    await new Promise((r) => setTimeout(r, 300));
    if (button) {
      await page.evaluate((label) => {
        const btn = Array.from(document.querySelectorAll("button")).find((b) => b.textContent.includes(label));
        btn?.click();
      }, button);
    }
    await new Promise((r) => setTimeout(r, wait));
    const path = join(OUT, `${slug}.png`);
    await page.screenshot({ path, type: "png" });
    console.log(`  📸 ${slug} → screenshots/${slug}.png`);
    captured++;
  }

  await page.evaluate(() => window.__goToView("files"));
  await new Promise((r) => setTimeout(r, 500));
  await page.screenshot({ path: join(OUT, "overview.png"), type: "png" });
  console.log("  📸 overview → screenshots/overview.png");

  await browser.close();
  preview.kill("SIGTERM");

  for (const stale of ["analysis_file_browser", "collection_disk_imaging", "compress", "encrypt", "extract", "inspect"]) {
    await rm(join(OUT, `${stale}.png`), { force: true });
  }

  console.log(`✅ Captured ${captured + 1} screenshots via Chrome headless`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
