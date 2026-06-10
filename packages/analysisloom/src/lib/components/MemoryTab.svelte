<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let result = $state(null);
  let jsonPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Memory Analysis Bridge",
      hint: "Import Volatility 3 JSON output — processes, network, DLLs from memory dumps",
      browse: "Browse",
      parse: "Parse JSON",
      processes: "Processes",
      network: "Network",
      jsonPath: "Volatility JSON path",
    },
    id: {
      title: "Jembatan Analisis Memori",
      hint: "Impor output JSON Volatility 3 — proses, jaringan, DLL dari dump memori",
      browse: "Jelajah",
      parse: "Parsing JSON",
      processes: "Proses",
      network: "Jaringan",
      jsonPath: "Path JSON Volatility",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function pick() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "Volatility JSON", extensions: ["json"] }],
    });
    if (picked) jsonPath = picked;
  }

  async function parse() {
    if (!jsonPath) return;
    busy = true;
    try {
      result = await timeoutPromise(invoke("parse_volatility_json", { path: jsonPath }), 60000);
      msg = `✅ ${result.processes.length} processes, ${result.networks.length} network connections`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Memory",
          filePath: jsonPath,
              eventType: `volatility_${result.processes.length}`,
            }).catch(() => {});
      }
    } catch (e) {
      result = null;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!jsonPath) {
      result = null;
    }
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")}</p>
  <div class="row">
    <input type="text" bind:value={jsonPath} placeholder={t("jsonPath")} disabled={busy} />
    <button onclick={pick} disabled={busy} class="btn">{t("browse")}</button>
    <button onclick={parse} disabled={busy || !jsonPath} class="btn-primary">{t("parse")}</button>
  </div>
  {#if result}
    <div class="sections">
      <section>
        <h4>{t("processes")} ({result.processes.length})</h4>
        {#each result.processes.slice(0, 40) as p}
          <div class="line"><span class="pid">{p.pid}</span> {p.name} <span class="cmd">{p.cmdline}</span></div>
        {/each}
      </section>
      {#if result.networks.length}
        <section>
          <h4>{t("network")} ({result.networks.length})</h4>
          {#each result.networks.slice(0, 30) as n}
            <div class="line">{n.protocol} {n.localAddr} → {n.foreignAddr} [{n.state}]</div>
          {/each}
        </section>
      {/if}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  section { margin-bottom: 16px; }
  h4 { margin: 0 0 8px; font-size: 13px; }
  .line { font-size: 11px; padding: 3px 0; border-bottom: 1px solid var(--divider); font-family: var(--mono); }
  .pid { color: var(--primary); font-weight: 600; }
  .cmd { color: var(--text-muted); }
</style>
