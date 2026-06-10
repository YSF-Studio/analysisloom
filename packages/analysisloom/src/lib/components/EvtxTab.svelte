<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let logPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Windows Event Log (EVTX)",
      hint: "Security events — 4624/4625 logon, 4688 process create, 4104 PowerShell, 7045 service install",
      browse: "Browse",
      parse: "Parse EVTX",
      scanFolder: "Scan Folder",
      id: "ID",
      time: "Time",
      channel: "Channel",
      message: "Message",
      relevance: "Relevance",
      parsed: "parsed",
      events: "events",
      logPath: "Security.evtx path",
    },
    id: {
      title: "Log Peristiwa Windows (EVTX)",
      hint: "Event keamanan — 4624/4625 login, 4688 proses, 4104 PowerShell, 7045 instalasi service",
      browse: "Jelajah",
      parse: "Parsing EVTX",
      scanFolder: "Pindai Folder",
      id: "ID",
      time: "Waktu",
      channel: "Channel",
      message: "Pesan",
      relevance: "Relevansi",
      parsed: "diurai",
      events: "event",
      logPath: "Path Security.evtx",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

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

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")}</p>
  <div class="row">
    <input type="text" bind:value={logPath} placeholder={t("logPath")} disabled={busy} />
    <button onclick={pick} disabled={busy} class="btn">{t("browse")}</button>
    <button onclick={analyze} disabled={busy || !logPath} class="btn-primary">{t("parse")}</button>
    <button onclick={scanDir} disabled={busy} class="btn">{t("scanFolder")}</button>
  </div>
  {#each results as res}
    <div class="block">
      <h4>{res.logPath.split(/[/\\]/).pop()} — {res.events.length} {t("events")} ({res.recordsParsed} {t("parsed")})</h4>
      <div class="events">
        <div class="head"><span>{t("id")}</span><span>{t("time")}</span><span>{t("channel")}</span><span>{t("message")}</span><span>{t("relevance")}</span></div>
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
