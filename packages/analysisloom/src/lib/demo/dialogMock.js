import { DEMO_IMAGE } from "./mockData.js";

export async function open(opts) {
  const exts = opts?.filters?.flatMap((f) => f.extensions) || [];
  if (exts.some((e) => ["dd", "raw", "img"].includes(e))) return DEMO_IMAGE;
  if (exts.some((e) => ["db", "sqlite"].includes(e))) return "/workspace/test-fixtures/messages.db";
  return "/workspace/test-fixtures/secret_password_log.txt";
}

export async function save() {
  return "/tmp/export.pdf";
}
