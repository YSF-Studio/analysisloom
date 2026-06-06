<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let rootPath = $state("");
  let detection = $state(null);
  let scanResult = $state(null);

  const PLATFORM_META = {
    windows: { icon: "🪟", label: "Windows", color: "#2563eb" },
    linux: { icon: "🐧", label: "Linux", color: "#f97316" },
    macos: { icon: "🍎", label: "macOS", color: "#a855f7" },
    mixed: { icon: "🔀", label: "Mixed OS", color: "#6366f1" },
    unknown: { icon: "❓", label: "Unknown", color: "#6b7280" },
  };

  async function pickFolder() {
    const dir = await open({ directory: true });
    if (dir) rootPath = typeof dir === "string" ? dir : rootPath;
  }

  async function detect() {
    if (!rootPath) return;
    busy = true;
    try {
      detection = await timeoutPromise(invoke("detect_evidence_platform", { root: rootPath }), 30000);
      scanResult = null;
      const pct = Math.round((detection.confidence || 0) * 100);
      msg = `✅ Detected: ${detection.primaryPlatform} (${pct}% confidence)`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function scanAll() {
    if (!rootPath) return;
    if (!activeCase?.id) {
      msg = "⚠️ Open a case first to record findings and timeline";
      return;
    }
    busy = true;
    try {
      scanResult = await timeoutPromise(
        invoke("scan_acquisition", { root: rootPath, caseId: activeCase.id }),
        300000
      );
      detection = scanResult.detection;
      const ok = scanResult.modules.filter((m) => m.status === "ok").length;
      msg = `✅ Acquisition scan: ${ok} modules, ${scanResult.findingsRecorded} findings, ${scanResult.timelineEvents} timeline events (${scanResult.durationMs}ms)`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  function platformInfo(id) {
    return PLATFORM_META[id] || PLATFORM_META.unknown;
  }
</script>

<div class="panel">
  <h3>Cross-Platform Acquisition</h3>
  <p class="hint">
    Analyze barang bukti dari Windows, Linux, atau macOS — deteksi otomatis platform lalu jalankan semua modul relevan
  </p>

  <div class="row">
    <input type="text" bind:value={rootPath} placeholder="Folder akuisisi / extracted evidence tree" disabled={busy} />
    <button onclick={pickFolder} disabled={busy}>Browse</button>
    <button onclick={detect} disabled={busy || !rootPath} class="btn-secondary">Detect OS</button>
    <button onclick={scanAll} disabled={busy || !rootPath || !activeCase} class="btn-primary">Scan All</button>
  </div>

  {#if detection}
    <div class="detect-card">
      <div class="primary">
        <span class="icon">{platformInfo(detection.primaryPlatform).icon}</span>
        <div>
          <strong>{platformInfo(detection.primaryPlatform).label}</strong>
          {#if detection.mixed}<span class="badge">Mixed acquisition</span>{/if}
          <span class="conf">{Math.round(detection.confidence * 100)}% confidence</span>
        </div>
      </div>
      <div class="signals">
        {#each detection.platforms.filter((p) => p.score > 0) as sig}
          <div class="signal">
            <span>{platformInfo(sig.platform).icon} {sig.platform}</span>
            <span class="score">{sig.score} indicators</span>
            <span class="inds">{sig.indicators.slice(0, 4).join(", ")}</span>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if scanResult}
    <div class="modules">
      <h4>Module Results</h4>
      {#each scanResult.modules as m}
        <div class="mod" class:error={m.status === "error"}>
          <span class="name">{m.module}</span>
          <span class="plat">{m.platform}</span>
          <span class="count">{m.itemCount}</span>
          <span class="msg">{m.message}</span>
        </div>
      {/each}
    </div>
  {/if}

  <div class="coverage">
    <h4>Platform Coverage</h4>
    <div class="grid">
      <div class="cov"><strong>🪟 Windows</strong> Registry, EVTX, Prefetch/LNK, NTFS image</div>
      <div class="cov"><strong>🐧 Linux</strong> auth.log, audit, syslog, journal, cron, bash history</div>
      <div class="cov"><strong>🍎 macOS</strong> KnowledgeC, plist, Unified Logs, TCC, Spotlight</div>
      <div class="cov"><strong>🌐 All OS</strong> Browser, Chat, Email, YARA, Carving, SQLite</div>
    </div>
  </div>
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  input { flex: 1; min-width: 200px; font-size: 12px; }
  .detect-card { border: 1px solid var(--divider); border-radius: 8px; padding: 12px; margin-bottom: 12px; }
  .primary { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .icon { font-size: 24px; }
  .badge { margin-left: 8px; font-size: 10px; background: rgba(99,102,241,0.15); padding: 2px 6px; border-radius: 4px; }
  .conf { display: block; font-size: 10px; color: var(--text-muted); }
  .signals { display: flex; flex-direction: column; gap: 4px; }
  .signal { display: grid; grid-template-columns: 100px 80px 1fr; gap: 8px; font-size: 10px; color: var(--text-secondary); }
  .score { color: var(--primary); }
  .inds { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; }
  .modules { margin-bottom: 12px; }
  .mod { display: grid; grid-template-columns: 120px 90px 50px 1fr; gap: 8px; font-size: 11px; padding: 5px 0; border-bottom: 1px solid var(--divider); }
  .mod.error { color: #ef4444; }
  .name { font-weight: 600; }
  .plat { color: var(--text-muted); font-size: 10px; }
  .count { font-weight: 600; color: var(--primary); }
  .coverage h4 { margin: 12px 0 6px; font-size: 12px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .cov { font-size: 10px; padding: 8px; border: 1px solid var(--divider); border-radius: 6px; color: var(--text-secondary); }
  .btn-secondary { font-size: 11px; }
</style>
