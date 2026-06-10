<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let result = $state(null);
  let pcapPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "PCAP Network Analyzer",
      hint: "TCP · UDP · DNS · HTTP flow reconstruction from packet captures",
      browse: "Browse",
      analyze: "Analyze PCAP",
      proto: "Proto",
      source: "Source",
      destination: "Destination",
      pkts: "Pkts",
      bytes: "Bytes",
      info: "Info",
      pcapPath: "PCAP file path",
    },
    id: {
      title: "Penganalisis Jaringan PCAP",
      hint: "Rekonstruksi alur TCP · UDP · DNS · HTTP dari packet capture",
      browse: "Jelajah",
      analyze: "Analisis PCAP",
      proto: "Protokol",
      source: "Sumber",
      destination: "Tujuan",
      pkts: "Pkt",
      bytes: "Byte",
      info: "Info",
      pcapPath: "Path file PCAP",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function pick() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "PCAP", extensions: ["pcap", "pcapng", "cap"] }],
    });
    if (picked) pcapPath = picked;
  }

  async function analyze() {
    if (!pcapPath) return;
    busy = true;
    try {
      result = await timeoutPromise(invoke("analyze_pcap", { path: pcapPath }), 120000);
      msg = `✅ ${result.packetsParsed} packets, ${result.flows.length} flows (${result.durationSecs.toFixed(2)}s)`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "PCAP",
          filePath: pcapPath,
          eventType: `pcap_${result.flows.length}`,
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
    if (!pcapPath) {
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
    <input type="text" bind:value={pcapPath} placeholder={t("pcapPath")} disabled={busy} />
    <button onclick={pick} disabled={busy} class="btn">{t("browse")}</button>
    <button onclick={analyze} disabled={busy || !pcapPath} class="btn-primary">{t("analyze")}</button>
  </div>
  {#if result}
    <p class="stats">{result.packetsParsed} packets · {result.flows.length} flows · {result.durationSecs.toFixed(2)}s span</p>
    <div class="flows">
      <div class="head"><span>{t("proto")}</span><span>{t("source")}</span><span>{t("destination")}</span><span>{t("pkts")}</span><span>{t("bytes")}</span><span>{t("info")}</span></div>
      {#each result.flows.slice(0, 60) as f}
        <div class="flow">
          <span>{f.protocol}</span>
          <span class="mono">{f.srcIp}:{f.srcPort}</span>
          <span class="mono">{f.dstIp}:{f.dstPort}</span>
          <span>{f.packetCount}</span>
          <span>{f.bytes}</span>
          <span class="info">{f.info}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .stats { font-size: 12px; color: var(--text-secondary); margin: 0 0 8px; }
  .flows .head, .flow { display: grid; grid-template-columns: 50px 1.2fr 1.2fr 50px 70px 1.5fr; gap: 6px; font-size: 11px; padding: 4px 0; }
  .flows .head { font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--divider); }
  .mono { font-family: var(--mono); font-size: 10px; }
  .info { color: var(--primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
