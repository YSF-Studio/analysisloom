<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let rootPath = $state("");

  async function scan() {
    const root = rootPath || (await open({ directory: true }));
    if (!root) return;
    rootPath = typeof root === "string" ? root : rootPath;
    busy = true;
    try {
      results = await timeoutPromise(invoke("scan_browser_artifacts", { root: rootPath }), 120000);
      msg = `✅ ${results.length} browser databases analyzed`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Browser",
          filePath: rootPath,
          eventType: `browser_${results.reduce((a, r) => a + r.artifacts.length, 0)}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Browser Artifacts</h3>
  <p class="hint">Chrome · Firefox · Safari · Edge — history, downloads, bookmarks</p>
  <div class="row">
    <input type="text" bind:value={rootPath} placeholder="/Users/.../AppData or evidence folder" disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">Scan Browsers</button>
  </div>
  {#each results as res}
    <div class="browser-block">
      <h4>{res.browser} — {res.artifacts.length} entries</h4>
      <p class="db">{res.dbPath}</p>
      <div class="artifacts">
        {#each res.artifacts.slice(0, 50) as a}
          <div class="art">
            <span class="type">{a.artifactType}</span>
            <span class="url">{a.url}</span>
            <span class="title">{a.title}</span>
            <span class="visits">{a.visitCount}× · {a.lastVisit}</span>
          </div>
        {/each}
      </div>
    </div>
  {/each}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .browser-block { margin-bottom: 16px; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; }
  .db { font-size: 10px; color: var(--text-muted); font-family: var(--mono); margin: 0 0 8px; }
  .art { display: grid; grid-template-columns: 70px 2fr 1fr auto; gap: 8px; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--divider); }
  .url { overflow: hidden; text-overflow: ellipsis; color: var(--primary); }
  .visits { color: var(--text-muted); white-space: nowrap; }
</style>
