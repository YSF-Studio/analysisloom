<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let hivePath = $state("");

  async function pickHive() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "Registry Hive", extensions: ["dat", "DAT", ""] }],
    });
    if (picked) hivePath = picked;
  }

  async function analyze() {
    if (!hivePath) return;
    busy = true;
    try {
      const r = await timeoutPromise(invoke("analyze_registry_hive", { path: hivePath }), 120000);
      results = [r];
      msg = `✅ ${r.findings.length} registry artifacts from ${r.hiveType}`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Registry",
          filePath: hivePath,
          eventType: `registry_${r.findings.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function scanDir() {
    const dir = await open({ directory: true });
    if (!dir) return;
    busy = true;
    try {
      results = await timeoutPromise(invoke("scan_registry_directory", { dir }), 120000);
      msg = `✅ Scanned ${results.length} hives`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Registry Analyzer</h3>
  <p class="hint">SAM · SYSTEM · SOFTWARE · NTUSER.DAT — USB history, UserAssist, Shellbags, MRU, Run keys</p>
  <div class="row">
    <input type="text" bind:value={hivePath} placeholder="/path/to/SYSTEM or NTUSER.DAT" disabled={busy} />
    <button onclick={pickHive} disabled={busy} class="btn">Browse</button>
    <button onclick={analyze} disabled={busy || !hivePath} class="btn-primary">Analyze Hive</button>
    <button onclick={scanDir} disabled={busy} class="btn">Scan Folder</button>
  </div>
  {#each results as res}
    <div class="hive-block">
      <h4>{res.hiveType} — {res.findings.length} findings ({res.keysScanned} keys)</h4>
      <div class="findings">
        {#each res.findings as f}
          <div class="finding">
            <span class="cat pill-{f.category}">{f.category}</span>
            <span class="key">{f.keyPath}</span>
            <span class="val">{f.valueName}: {f.valueData}</span>
            <span class="rel">{f.forensicRelevance}</span>
          </div>
        {/each}
      </div>
    </div>
  {/each}
</div>

<style>
  .panel { height: 100%; display: flex; flex-direction: column; gap: 8px; }
  h3 { margin: 0; font-size: 15px; }
  .hint { margin: 0; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  input { flex: 1; min-width: 200px; font-size: 12px; }
  .hive-block { flex: 1; min-height: 0; overflow: auto; border: 1px solid var(--divider); border-radius: 8px; padding: 8px; }
  .findings { font-size: 11px; }
  .finding { display: grid; grid-template-columns: 80px 1fr 1.5fr auto; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--divider); }
  .cat { font-size: 10px; padding: 2px 6px; border-radius: 8px; font-weight: 600; }
  .key { font-family: var(--mono); color: var(--text-secondary); }
  .val { overflow: hidden; text-overflow: ellipsis; }
  .rel { color: var(--text-muted); font-size: 10px; }
</style>
