import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    headless: true,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "cd packages/analysisloom && E2E=1 npm run build && E2E=1 npx vite preview --host 127.0.0.1 --port 4175",
    port: 4175,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
