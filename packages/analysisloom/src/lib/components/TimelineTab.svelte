<script>
  import { invoke } from "@tauri-apps/api/core";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let events = $state([]);
  let superMode = $state(true);
  let viewMode = $state("gantt");

  const SOURCE_COLORS = {
    NTFS: "#6366f1",
    Registry: "#8b5cf6",
    Browser: "#06b6d4",
    YARA: "#ef4444",
    Memory: "#f59e0b",
    EVTX: "#3b82f6",
    macOS: "#a855f7",
    PCAP: "#10b981",
    Windows: "#2563eb",
    Email: "#ec4899",
    Chat: "#14b8a6",
    Linux: "#f97316",
    Stego: "#eab308",
    Findings: "#dc2626",
    general: "#6b7280",
  };

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

  function parseTs(ts) {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d.getTime();
  }

  let ganttData = $derived.by(() => {
    const parsed = events
      .map((e) => ({
        ...e,
        ms: parseTs(e.timestamp),
        src: e.source || "general",
        cat: e.category || e.eventType || "",
        label: e.eventType || e.event_type || "",
        path: e.filePath || e.file_path || "",
      }))
      .filter((e) => e.ms !== null);

    if (parsed.length === 0) return { sources: [], min: 0, max: 1, span: 1 };

    const min = Math.min(...parsed.map((e) => e.ms));
    const max = Math.max(...parsed.map((e) => e.ms));
    const span = Math.max(max - min, 1);

    const bySource = {};
    for (const e of parsed) {
      if (!bySource[e.src]) bySource[e.src] = [];
      bySource[e.src].push(e);
    }

    const sources = Object.keys(bySource).sort();
    return { sources, bySource, min, max, span };
  });

  function barLeft(ms, min, span) {
    return ((ms - min) / span) * 100;
  }

  function sourceColor(src) {
    for (const [key, color] of Object.entries(SOURCE_COLORS)) {
      if (src.toUpperCase().includes(key.toUpperCase())) return color;
    }
    return SOURCE_COLORS.general;
  }
</script>

<div class="timeline-panel">
  <div class="head">
    <h3>Timeline Analysis</h3>
    <label class="toggle">
      <input type="checkbox" bind:checked={superMode} />
      Super Timeline (multi-source correlation)
    </label>
    <div class="view-toggle">
      <button class:active={viewMode === "gantt"} onclick={() => (viewMode = "gantt")}>Gantt</button>
      <button class:active={viewMode === "table"} onclick={() => (viewMode = "table")}>Table</button>
    </div>
    <button onclick={loadTimeline} disabled={busy || !activeCase} class="btn-primary">Load Timeline</button>
  </div>

  {#if events.length && viewMode === "gantt"}
    <div class="gantt-wrap">
      <div class="gantt-axis">
        <span class="axis-label">{new Date(ganttData.min).toLocaleString()}</span>
        <span class="axis-label right">{new Date(ganttData.max).toLocaleString()}</span>
      </div>
      <div class="gantt">
        {#each ganttData.sources as src}
          <div class="gantt-row">
            <span class="row-label" style="color: {sourceColor(src)}">{src}</span>
            <div class="row-track">
              {#each ganttData.bySource[src].slice(0, 30) as evt, i}
                <div
                  class="bar sev-{evt.severity || 'info'}"
                  style="left: {barLeft(evt.ms, ganttData.min, ganttData.span)}%; background: {sourceColor(src)}"
                  title="{evt.label} — {evt.path}"
                >
                  <span class="bar-tip">{evt.label}</span>
                </div>
              {/each}
            </div>
          </div>
        {/each}
      </div>
      <div class="legend">
        {#each ganttData.sources as src}
          <span class="leg-item"><span class="dot" style="background: {sourceColor(src)}"></span>{src}</span>
        {/each}
      </div>
    </div>
  {:else if events.length}
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
    <p class="empty">Load Super Timeline to correlate NTFS, registry, browser, YARA, and memory events — switch to Gantt for graphical view</p>
  {/if}
</div>

<style>
  .timeline-panel { height: 100%; }
  .head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  h3 { margin: 0; font-size: 15px; }
  .toggle { font-size: 11px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
  .view-toggle { display: flex; gap: 2px; }
  .view-toggle button { font-size: 11px; padding: 4px 10px; border: 1px solid var(--divider); background: transparent; color: var(--text-secondary); border-radius: 4px; cursor: pointer; }
  .view-toggle button.active { background: var(--primary); color: #fff; border-color: var(--primary); }
  .gantt-wrap { border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 70vh; }
  .gantt-axis { display: flex; justify-content: space-between; padding: 6px 12px 6px 100px; font-size: 10px; color: var(--text-muted); border-bottom: 1px solid var(--divider); }
  .gantt { padding: 8px 0; }
  .gantt-row { display: grid; grid-template-columns: 90px 1fr; gap: 8px; align-items: center; padding: 4px 12px; min-height: 28px; }
  .row-label { font-size: 10px; font-weight: 600; text-align: right; overflow: hidden; text-overflow: ellipsis; }
  .row-track { position: relative; height: 20px; background: rgba(255,255,255,0.03); border-radius: 4px; }
  .bar { position: absolute; top: 2px; width: 8px; height: 16px; border-radius: 3px; cursor: pointer; opacity: 0.85; transition: transform 0.15s; }
  .bar:hover { transform: scaleY(1.3); opacity: 1; z-index: 2; }
  .bar-tip { display: none; }
  .legend { display: flex; flex-wrap: wrap; gap: 10px; padding: 8px 12px; border-top: 1px solid var(--divider); font-size: 10px; }
  .leg-item { display: flex; align-items: center; gap: 4px; color: var(--text-secondary); }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
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
