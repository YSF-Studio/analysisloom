import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshot = process.env.SCREENSHOT === "1";

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  define: {
    "import.meta.env.VITE_SCREENSHOT": JSON.stringify(screenshot),
  },
  resolve: screenshot
    ? {
        alias: {
          "@tauri-apps/api/core": path.resolve(__dirname, "src/lib/demo/tauriMock.js"),
          "@tauri-apps/plugin-dialog": path.resolve(__dirname, "src/lib/demo/dialogMock.js"),
          "@tauri-apps/api/window": path.resolve(__dirname, "src/lib/demo/windowMock.js"),
        },
      }
    : {},
  server: { port: 1421, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
  build: { target: "esnext" },
});
