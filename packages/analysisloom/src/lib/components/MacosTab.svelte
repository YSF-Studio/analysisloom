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
      results = await timeoutPromise(invoke("scan_macos_artifacts", { root: rootPath }), 120000);
      msg = `✅ ${results.length} macOS artifact sources`;
      if (activeCase?.id) {
        const count = results.reduce((a, r) => a + r.artifacts.length, 0);
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "macOS",
          filePath: rootPath,
          eventType: `macos_${count}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>macOS Artifact Analyzer</h3>
  <p class="hint">KnowledgeC.db · Unified Log (.logarchive) · plist · Spotlight · DataDetectors · TCC</p>
  <div class="row">
    <input type="text" bind:value={rootPath} placeholder="/Users/.../Library or evidence folder" disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">Scan macOS Artifacts</button>
  </div>
  {#each results as res}
    <div class="block">
      <h4>{res.sourcePath.split(/[/\\]/).pop()} — {res.artifacts.length} entries</h4>
      <div class="arts">
        {#each res.artifacts.slice(0, 40) as a}
          <div class="art">
            <span class="type">{a.artifactType}</span>
            <span class="key">{a.key}</span>
            <span class="val">{a.value}</span>
            <span class="rel">{a.forensicRelevance}</span>
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
  .block { margin-bottom: 16px; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; }
  .art { display: grid; grid-template-columns: 90px 1fr 1fr 1fr; gap: 8px; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--divider); }
  .type { color: var(--primary); font-weight: 600; }
  .rel { color: var(--text-muted); }
</style>
