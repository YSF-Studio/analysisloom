<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import SectionHeader from "./SectionHeader.svelte";
  import SeverityBadge from "./SeverityBadge.svelte";
  import ProgressBar from "./ProgressBar.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";
  import { highlightSegments } from "../highlight.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise, evidencePaths = [] } = $props();
  let matches = $state([]);
  let rulesPath = $state("");
  let ruleCount = $state(0);
  let expanded = $state({});

  $effect(() => {
    invoke("yara_builtin_rule_count").then((n) => (ruleCount = n)).catch(() => {});
  });

  function toggleExpand(i) {
    expanded = { ...expanded, [i]: !expanded[i] };
  }

  async function scan() {
    if (!evidencePaths.length) {
      msg = "⚠️ Add evidence files to the case first";
      return;
    }
    busy = true;
    matches = [];
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
  <SectionHeader
    title="YARA Scanner"
    hint="{ruleCount} built-in rules + optional custom .yar — malware classification & IOC detection"
  />
  <div class="row">
    <input type="text" bind:value={rulesPath} placeholder="Optional custom rules (.yar)" disabled={busy} />
    <button onclick={pickRules} disabled={busy} class="btn">Load Rules</button>
    <button onclick={scan} disabled={busy || !activeCase} class="btn-primary">Scan Evidence</button>
  </div>

  {#if busy}
    <ProgressBar indeterminate label="Scanning evidence with YARA rules…" />
    <LoadingSkeleton rows={5} columns={4} />
  {:else if matches.length}
    <div class="matches">
      <div class="head">
        <span>Rule</span><span>File</span><span>Offset</span><span>Severity</span><span>Match Preview</span>
      </div>
      {#each matches as m, i}
        <div class="row-match">
          <span class="rule">{m.ruleName}</span>
          <span class="mono file" title={m.filePath}>{m.filePath}</span>
          <span class="mono">0x{m.offset.toString(16)}</span>
          <span><SeverityBadge severity={m.severity} /></span>
          <button class="snippet-btn" onclick={() => toggleExpand(i)}>
            {expanded[i] ? "Hide" : "Show"} snippet
          </button>
        </div>
        {#if expanded[i] || matches.length <= 8}
          <div class="snippet-row">
            <span class="snippet-label">String: <code>{m.matchedString}</code></span>
            <pre class="snippet">{#each highlightSegments(m.matchSnippet || m.matchedString, m.matchedString) as seg}{#if seg.match}<mark class="hl">{seg.text}</mark>{:else}{seg.text}{/if}{/each}</pre>
          </div>
        {/if}
      {/each}
    </div>
  {:else}
    <p class="empty">Scan case evidence with built-in + custom YARA rules</p>
  {/if}
</div>

<style>
  .panel { height: 100%; display: flex; flex-direction: column; }
  .row { display: flex; gap: 8px; margin-bottom: 12px; flex-shrink: 0; }
  input { flex: 1; font-size: 12px; }
  .matches {
    border: 1px solid var(--divider); border-radius: 8px; overflow: auto;
    max-height: 60vh; font-size: 12px; flex: 1;
  }
  .head, .row-match {
    display: grid; grid-template-columns: 1.1fr 1.6fr 90px 110px 100px;
    gap: 8px; padding: 8px 12px; align-items: center;
  }
  .head {
    font-weight: 600; font-size: 11px; color: var(--text-secondary);
    position: sticky; top: 0; background: var(--surface-header); z-index: 1;
    border-bottom: 1px solid var(--divider);
  }
  .row-match { border-bottom: 1px solid var(--divider); }
  .row-match:hover { background: var(--primary-bg); }
  .rule { font-weight: 600; }
  .mono { font-family: var(--mono); font-size: 11px; }
  .file { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .snippet-row {
    padding: 8px 12px 10px; background: var(--surface-muted);
    border-bottom: 1px solid var(--divider);
  }
  .snippet-label { font-size: 10px; color: var(--text-muted); display: block; margin-bottom: 4px; }
  .snippet-label code { color: var(--primary); }
  .snippet {
    margin: 0; padding: 8px; border-radius: 6px; background: var(--surface-code); color: var(--text-code);
    font-family: var(--mono); font-size: 10px; white-space: pre-wrap; word-break: break-all;
    max-height: 80px; overflow: auto;
  }
  mark.hl { background: var(--mark-bg); color: var(--text-highlight); padding: 0 1px; border-radius: 2px; }
  .snippet-btn {
    padding: 2px 8px; font-size: 10px; border-radius: 4px;
    border: 1px solid var(--divider); background: transparent;
    color: var(--primary); cursor: pointer;
  }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
