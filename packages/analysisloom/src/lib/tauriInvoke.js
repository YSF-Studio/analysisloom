import { invoke as tauriInvoke } from "@tauri-apps/api/core";

/**
 * Safe Tauri IPC wrapper — logs failures to DevTools Console.
 * @template T
 * @param {string} cmd
 * @param {Record<string, unknown>} [args]
 * @returns {Promise<T>}
 */
export async function tauriInvoke(cmd, args = {}) {
  try {
    return await tauriInvoke(cmd, args);
  } catch (err) {
    console.error(`[Tauri IPC] invoke('${cmd}') failed:`, err);
    throw err;
  }
}
