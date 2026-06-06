/** Light / dark theme — persisted in localStorage. */

export const THEME_STORAGE_KEY = "analysisloom-theme";

/** @typedef {"dark" | "light"} ThemeId */

/** @returns {ThemeId} */
export function getStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* private mode / SSR */
  }
  return "dark";
}

/** @param {ThemeId} theme */
export function applyTheme(theme) {
  const root = document.documentElement;
  root.classList.toggle("theme-light", theme === "light");
  root.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    /* ignore */
  }
  return theme;
}

/** @param {ThemeId} theme */
export function setTheme(theme) {
  return applyTheme(theme);
}

/** @param {ThemeId} current */
export function toggleTheme(current) {
  return applyTheme(current === "dark" ? "light" : "dark");
}
