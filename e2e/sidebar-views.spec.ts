import { test, expect } from "@playwright/test";
import { SIDEBAR_NAV_LABELS, collectConsoleErrors } from "./helpers";

test.describe("All sidebar views", () => {
  test("navigate every sidebar entry without IPC fatals", async ({ page }) => {
    const { fatal } = collectConsoleErrors(page);
    await page.goto("/");

    for (const label of SIDEBAR_NAV_LABELS) {
      const btn = page.locator(".sidebar .nav-item").filter({ hasText: label }).first();
      await btn.click();
      await expect(btn).toHaveClass(/active/);
      await page.waitForTimeout(150);
    }

    expect(fatal(), `IPC/console fatals:\n${fatal().join("\n")}`).toEqual([]);
  });
});
