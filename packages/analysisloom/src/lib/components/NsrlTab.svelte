<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { busy = $bindable(), msg = $bindable(), timeoutPromise, selectedFile = "" } = $props();
  let result = $state(null);
  let stats = $state({ hashCount: 0 });
  let importPath = $state("");

  async function loadStats() {
    stats = await invoke("nsrl_stats");
  }

  $effect(() => { loadStats(); });

  async function lookupFile() {
    if (!selectedFile) {
      msg = "⚠️ Select a file in Inspector or NTFS browser";
      return;
    }
    busy = true;
    try {
      result = await timeoutPromise(invoke("nsrl_lookup_file", { path: selectedFile }), 30000);
      msg = result.knownGood ? "✅ Known-good (NSRL match)" : "⚠️ Unknown — requires examination";
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function importNsrl() {
    const picked = await open({ multiple: false, filters: [{ name: "NSRL", extensions: ["txt", "csv", "db"] }] });
    if (!picked) return;
    busy = true;
    try {
      const n = await invoke("nsrl_import", { path: picked });
      msg = `✅ Imported ${n} NSRL hashes`;
      await loadStats();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function seed() {
    busy = true;
    await invoke("nsrl_seed_builtin");
    await loadStats();
    msg = "✅ Built-in NSRL seed loaded";
    busy = false;
  }
</script>

<div class="panel">
  <h3>NSRL Hash Lookup</h3>
  <p class="hint">NIST National Software Reference Library — filter known-good OS files ({stats.hashCount} hashes loaded)</p>
  <div class="actions">
    <button onclick={lookupFile} disabled={busy || !selectedFile} class="btn-primary">Lookup Selected File</button>
    <button onclick={importNsrl} disabled={busy} class="btn">Import NSRL File</button>
    <button onclick={seed} disabled={busy} class="btn">Load Seed Set</button>
  </div>
  {#if result}
    <div class="result" class:known={result.knownGood}>
      <p><strong>SHA-256:</strong> <span class="mono">{result.sha256}</span></p>
      <p><strong>Status:</strong> {result.knownGood ? "Known Good ✓" : "Unknown — investigate"}</p>
      {#if result.fileName}<p><strong>NSRL Name:</strong> {result.fileName}</p>{/if}
      {#if result.product}<p><strong>Product:</strong> {result.product}</p>{/if}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .result { padding: 16px; border-radius: 8px; border: 1px solid var(--divider); font-size: 12px; }
  .result.known { border-color: var(--success); background: var(--success-bg); }
  .mono { font-family: var(--mono); font-size: 11px; word-break: break-all; }
</style>
