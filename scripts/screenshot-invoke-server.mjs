#!/usr/bin/env node
/**
 * HTTP invoke proxy → Rust screenshot_bridge (real forensic commands on fixture files).
 */
import { spawn } from "child_process";
import http from "http";
import { createInterface } from "readline";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const TAURI = join(ROOT, "packages/analysisloom/src-tauri");
const PORT = Number(process.env.SCREENSHOT_BRIDGE_PORT || 4174);
const FIXTURES_DIR = process.env.FIXTURES_DIR || join(ROOT, "test-fixtures");

let bridgeProc = null;
let bridgeReady = false;
let reqId = 0;
let chain = Promise.resolve();
const pending = new Map();

function startBridge() {
  return new Promise((resolve, reject) => {
    bridgeProc = spawn(
      "cargo",
      ["run", "--quiet", "--example", "screenshot_bridge"],
      {
        cwd: TAURI,
        stdio: ["pipe", "pipe", "inherit"],
        env: {
          ...process.env,
          ANALYSISLOOM_FIXTURES_DIR: FIXTURES_DIR,
        },
      }
    );

    const rl = createInterface({ input: bridgeProc.stdout });
    rl.on("line", (line) => {
      try {
        const msg = JSON.parse(line);
        const p = pending.get(msg.id);
        if (p) {
          pending.delete(msg.id);
          if (msg.ok) p.resolve(msg.result);
          else p.reject(msg.error || "bridge error");
        }
      } catch (e) {
        console.error("[bridge] bad response:", line, e);
      }
    });

    bridgeProc.on("error", reject);
    bridgeProc.stdin.on("error", () => {});
    setTimeout(() => {
      bridgeReady = true;
      resolve();
    }, 8000);
  });
}

function bridgeInvoke(cmd, args) {
  const id = ++reqId;
  const payload = JSON.stringify({ id, cmd, args }) + "\n";
  const promise = new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`bridge timeout: ${cmd}`));
      }
    }, 180000);
  });
  chain = chain.then(() => {
    if (!bridgeProc?.stdin?.writable) {
      return Promise.reject(new Error("bridge not running"));
    }
    bridgeProc.stdin.write(payload);
    return promise;
  });
  return chain;
}

function startHttp() {
  const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }
    if (req.method !== "POST" || req.url !== "/invoke") {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      try {
        const { cmd, args } = JSON.parse(body);
        const result = await bridgeInvoke(cmd, args ?? {});
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ ok: true, result }));
      } catch (e) {
        res.writeHead(500, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ ok: false, error: String(e) }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(PORT, "127.0.0.1", () => {
      console.log(`▶ Screenshot bridge HTTP on http://127.0.0.1:${PORT}`);
      resolve(server);
    });
  });
}

export async function main() {
  console.log(`▶ Starting Rust screenshot bridge (fixtures: ${FIXTURES_DIR})...`);
  await startBridge();
  if (!bridgeReady) throw new Error("bridge failed to start");
  const server = await startHttp();
  return { server, bridgeProc, shutdown };
}

export function shutdown() {
  for (const [, p] of pending) {
    p.reject(new Error("bridge shutdown"));
  }
  pending.clear();
  if (bridgeProc) {
    bridgeProc.kill("SIGTERM");
    bridgeProc = null;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
