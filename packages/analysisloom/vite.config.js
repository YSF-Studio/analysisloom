import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshot = process.env.SCREENSHOT === "1";
const e2e = process.env.E2E === "1";
const screenshotReal = process.env.SCREENSHOT_REAL !== "0";
const useTauriMock = screenshot || e2e;
const fixturesDir =
  process.env.FIXTURES_DIR || path.resolve(__dirname, "../../test-fixtures");
const bridgeUrl = process.env.SCREENSHOT_BRIDGE_URL || "http://127.0.0.1:4174";
const tauriCore = useTauriMock
  ? screenshot && screenshotReal
    ? "src/lib/demo/tauriBridgeMock.js"
    : "src/lib/demo/tauriMock.js"
  : null;

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  define: {
    "import.meta.env.VITE_SCREENSHOT": JSON.stringify(screenshot),
    "import.meta.env.VITE_SCREENSHOT_REAL": JSON.stringify(screenshot && screenshotReal),
    "import.meta.env.VITE_SCREENSHOT_LIGHT": JSON.stringify(screenshot),
    "import.meta.env.VITE_FIXTURES_DIR": JSON.stringify(fixturesDir),
    "import.meta.env.VITE_BRIDGE_URL": JSON.stringify(bridgeUrl),
  },
  resolve: tauriCore
    ? {
        alias: {
          "@tauri-apps/api/core": path.resolve(__dirname, tauriCore),
          "@tauri-apps/plugin-dialog": path.resolve(__dirname, "src/lib/demo/dialogMock.js"),
          "@tauri-apps/api/window": path.resolve(__dirname, "src/lib/demo/windowMock.js"),
        },
      }
    : {},
  server: { port: 1421, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
  build: { target: "esnext" },
});
