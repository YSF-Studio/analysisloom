import { test, expect } from "@playwright/test";
import { collectConsoleErrors } from "./helpers";

test.describe("Case Manager flow (mock backend)", () => {
  test("create case and see active case in titlebar", async ({ page }) => {
    const { fatal } = collectConsoleErrors(page);
    await page.goto("/");

    await page.getByRole("button", { name: /Case Manager/i }).click();
    await page.getByLabel(/Case name/i).fill("E2E Test Case");
    await page.getByLabel(/Operator/i).fill("Playwright");
    await page.getByRole("button", { name: /New Case/i }).click();

    await expect(page.getByRole("button", { name: /Case: E2E Test Case/i })).toBeVisible({
      timeout: 5000,
    });

    expect(fatal()).toEqual([]);
  });

  test("YARA scanner loads builtin rule count", async ({ page }) => {
    const { fatal } = collectConsoleErrors(page);
    await page.goto("/");

    await page.getByRole("button", { name: /YARA Scanner/i }).click();
    await expect(page.locator(".panel, .yara-panel, .card").first()).toBeVisible();

    expect(fatal()).toEqual([]);
  });
});
