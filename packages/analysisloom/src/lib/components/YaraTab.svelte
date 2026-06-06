<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise, evidencePaths = [] } = $props();
  let matches = $state([]);
  let rulesPath = $state("");
  let ruleCount = $state(0);

  $effect(() => {
    invoke("yara_builtin_rule_count").then((n) => (ruleCount = n)).catch(() => {});
  });

  async function scan() {
    if (!evidencePaths.length) {
      msg = "⚠️ Add evidence files to the case first";
      return;
    }
    busy = true;
    try {
      matches = await timeoutPromise(
        invoke("yara_scan_paths", { paths: evidencePaths, rulesPath: rulesPath || null }),
        120000
      );
      msg = `✅ ${matches.length} YARA matches`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "YARA",
          filePath: evidencePaths[0] || "",
          eventType: `yara_${matches.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function pickRules() {
    const picked = await open({ multiple: false, filters: [{ name: "YARA Rules", extensions: ["yar", "yara"] }] });
    if (picked) rulesPath = picked;
  }
</script>

<div class="panel">
  <h3>YARA Scanner</h3>
  <p class="hint">{ruleCount} built-in rules + optional custom .yar — malware classification & IOC detection</p>
  <div class="row">
    <input type="text" bind:value={rulesPath} placeholder="Optional custom rules (.yar)" disabled={busy} />
    <button onclick={pickRules} disabled={busy} class="btn">Load Rules</button>
    <button onclick={scan} disabled={busy || !activeCase} class="btn-primary">Scan Evidence</button>
  </div>
  {#if matches.length}
    <div class="matches">
      <div class="head"><span>Rule</span><span>File</span><span>Offset</span><span>Severity</span></div>
      {#each matches as m}
        <div class="row-match sev-{m.severity}">
          <span>{m.ruleName}</span>
          <span class="mono">{m.filePath}</span>
          <span class="mono">0x{m.offset.toString(16)}</span>
          <span>{m.severity}</span>
        </div>
      {/each}
    </div>
  {:else if !busy}
    <p class="empty">Scan case evidence with built-in + custom YARA rules</p>
  {/if}
</div>

<style>
  .panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .matches { border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 60vh; font-size: 12px; }
  .head, .row-match { display: grid; grid-template-columns: 1.2fr 2fr 100px 80px; gap: 8px; padding: 8px 12px; border-bottom: 1px solid var(--divider); }
  .head { font-weight: 600; font-size: 11px; color: var(--text-secondary); }
  .mono { font-family: var(--mono); font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
  .sev-critical { background: rgba(239, 68, 68, 0.08); }
  .sev-high { background: rgba(245, 158, 11, 0.08); }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
