import { test, expect } from "@playwright/test";

const IGNORE_CONSOLE = [
  /favicon/i,
  /Failed to load resource.*favicon/i,
];

function isIgnoredError(text: string) {
  return IGNORE_CONSOLE.some((re) => re.test(text));
}

test.describe("AnalysisLoom GUI", () => {
  test("loads, navigates main views, no IPC/console fatals", async ({ page }) => {
    const errors: string[] = [];

    page.on("console", (msg) => {
      if (msg.type() === "error" && !isIgnoredError(msg.text())) {
        errors.push(msg.text());
      }
    });
    page.on("pageerror", (err) => errors.push(err.message));

    await page.goto("/");
    await expect(page.locator(".title-text")).toHaveText("AnalysisLoom");

    const navClicks = [
      /Case Manager/i,
      /NTFS Browser/i,
      /Timeline/i,
      /About/i,
      /Registry/i,
      /Cross-Platform Acquisition/i,
    ];

    for (const label of navClicks) {
      await page.getByRole("button", { name: label }).first().click();
      await page.waitForTimeout(300);
    }

    const fatal = errors.filter(
      (e) =>
        /not found/i.test(e) ||
        /UNHANDLED/i.test(e) ||
        /\[Tauri IPC\]/i.test(e) ||
        /FATAL:/i.test(e)
    );

    expect(fatal, `Console errors:\n${fatal.join("\n")}`).toEqual([]);
  });

  test("theme toggle and search bar are interactive", async ({ page }) => {
    await page.goto("/");
    const search = page.locator("#global-search");
    await search.fill("password");
    await expect(search).toHaveValue("password");

    const themeBtn = page.getByRole("button", { name: /Toggle light\/dark theme/i });
    await themeBtn.click();
    await expect(page.locator("html")).toHaveClass(/theme-light/);
  });
});
