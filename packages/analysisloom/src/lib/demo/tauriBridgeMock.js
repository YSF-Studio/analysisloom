/** Proxies Tauri invoke() to the Rust screenshot bridge (real fixture processing). */

const BRIDGE_URL =
  import.meta.env.VITE_BRIDGE_URL || "http://127.0.0.1:4174";

export async function invoke(cmd, args = {}) {
  const res = await fetch(`${BRIDGE_URL}/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, args }),
  });
  const data = await res.json();
  if (!data.ok) {
    throw typeof data.error === "string" ? data.error : JSON.stringify(data.error);
  }
  return data.result;
}
