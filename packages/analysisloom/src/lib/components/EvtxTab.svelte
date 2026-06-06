<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let logPath = $state("");

  async function pick() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "Windows Event Log", extensions: ["evtx"] }],
    });
    if (picked) logPath = picked;
  }

  async function analyze() {
    if (!logPath) return;
    busy = true;
    try {
      const r = await timeoutPromise(invoke("parse_evtx_log", { path: logPath }), 120000);
      results = [r];
      msg = `✅ ${r.events.length} security events from ${r.channel}`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "EVTX",
          filePath: logPath,
          eventType: `evtx_${r.events.length}`,
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
      results = await timeoutPromise(invoke("scan_evtx_directory", { dir }), 120000);
      msg = `✅ Scanned ${results.length} EVTX logs`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Windows Event Log (EVTX)</h3>
  <p class="hint">Security events — 4624/4625 logon, 4688 process create, 4104 PowerShell, 7045 service install</p>
  <div class="row">
    <input type="text" bind:value={logPath} placeholder="/path/to/Security.evtx" disabled={busy} />
    <button onclick={pick} disabled={busy} class="btn">Browse</button>
    <button onclick={analyze} disabled={busy || !logPath} class="btn-primary">Parse EVTX</button>
    <button onclick={scanDir} disabled={busy} class="btn">Scan Folder</button>
  </div>
  {#each results as res}
    <div class="block">
      <h4>{res.logPath.split(/[/\\]/).pop()} — {res.events.length} events ({res.recordsParsed} parsed)</h4>
      <div class="events">
        <div class="head"><span>ID</span><span>Time</span><span>Channel</span><span>Message</span><span>Relevance</span></div>
        {#each res.events.slice(0, 80) as e}
          <div class="ev sev-{e.level.toLowerCase()}">
            <span>{e.eventId}</span>
            <span class="ts">{e.timestamp}</span>
            <span>{e.channel}</span>
            <span class="msg">{e.message}</span>
            <span class="rel">{e.forensicRelevance}</span>
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
  .row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  input { flex: 1; min-width: 200px; font-size: 12px; }
  .block { margin-bottom: 16px; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; }
  .events .head, .ev { display: grid; grid-template-columns: 50px 140px 80px 2fr 1fr; gap: 6px; font-size: 11px; padding: 4px 0; }
  .events .head { font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--divider); }
  .msg { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rel { color: var(--primary); }
</style>
