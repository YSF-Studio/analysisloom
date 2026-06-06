<script>
  import { invoke } from "@tauri-apps/api/core";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let events = $state([]);
  let superMode = $state(true);

  async function loadTimeline() {
    if (!activeCase?.id) return;
    busy = true;
    try {
      if (superMode) {
        events = await timeoutPromise(invoke("get_super_timeline", { caseId: activeCase.id }), 30000);
        msg = `✅ Super Timeline: ${events.length} correlated events`;
      } else {
        events = await timeoutPromise(invoke("get_timeline", { caseId: activeCase.id }), 30000);
        msg = `✅ ${events.length} timeline events`;
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="timeline-panel">
  <div class="head">
    <h3>Timeline Analysis</h3>
    <label class="toggle">
      <input type="checkbox" bind:checked={superMode} />
      Super Timeline (multi-source correlation)
    </label>
    <button onclick={loadTimeline} disabled={busy || !activeCase} class="btn-primary">Load Timeline</button>
  </div>
  {#if events.length}
    <div class="timeline">
      <div class="thead">
        <span>Time</span><span>Source</span><span>Category</span><span>Event</span><span>Path</span>
      </div>
      {#each events.slice(0, 200) as evt}
        <div class="event sev-{evt.severity || 'info'}">
          <span class="ts">{evt.timestamp}</span>
          <span class="src">{evt.source || "—"}</span>
          <span class="cat">{evt.category || evt.eventType}</span>
          <span class="type">{evt.eventType || evt.event_type}</span>
          <span class="path">{evt.filePath || evt.file_path || ""}</span>
        </div>
      {/each}
    </div>
  {:else if !busy && activeCase}
    <p class="empty">Load Super Timeline to correlate NTFS, registry, browser, YARA, and memory events</p>
  {/if}
</div>

<style>
  .timeline-panel { height: 100%; }
  .head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  h3 { margin: 0; font-size: 15px; }
  .toggle { font-size: 11px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
  .timeline { font-size: 11px; border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 70vh; }
  .thead, .event { display: grid; grid-template-columns: 140px 90px 80px 1fr 1.5fr; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--divider); }
  .thead { font-weight: 600; color: var(--text-secondary); position: sticky; top: 0; background: rgba(0,0,0,0.4); }
  .ts { color: var(--text-secondary); white-space: nowrap; }
  .src { font-weight: 600; }
  .cat { color: var(--primary); font-size: 10px; }
  .path { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); }
  .sev-high { background: rgba(239, 68, 68, 0.05); }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
