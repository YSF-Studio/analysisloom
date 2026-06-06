import { VIEW_META, FORENSICS_NAV } from "../packages/analysisloom/src/lib/viewRegistry.js";

/** Sidebar button labels as rendered in App.svelte */
export const SIDEBAR_NAV_LABELS = [
  VIEW_META.cases.label,
  "Cross-Platform Acquisition",
  VIEW_META.timeline.label,
  VIEW_META.carving.label,
  VIEW_META.sqlite.label,
  VIEW_META.search.label,
  VIEW_META.files.label,
  ...FORENSICS_NAV.flatMap((g) => g.views.map((id) => VIEW_META[id].label)),
  VIEW_META.bookmarks.label,
  VIEW_META.encrypted.label,
  VIEW_META.report.label,
  VIEW_META.about.label,
];

export function collectConsoleErrors(page: import("@playwright/test").Page) {
  const errors: string[] = [];
  const IGNORE = [/favicon/i, /Failed to load resource.*favicon/i];

  page.on("console", (msg) => {
    if (msg.type() === "error" && !IGNORE.some((re) => re.test(msg.text()))) {
      errors.push(msg.text());
    }
  });
  page.on("pageerror", (err) => errors.push(err.message));

  return {
    errors,
    fatal: () =>
      errors.filter(
        (e) =>
          /not found/i.test(e) ||
          /UNHANDLED/i.test(e) ||
          /\[Tauri IPC\]/i.test(e) ||
          /FATAL:/i.test(e)
      ),
  };
}
