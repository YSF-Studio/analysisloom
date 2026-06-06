<script>
  import SegmentedControl from "./SegmentedControl.svelte";

  let { activeCase, busy = $bindable(), msg = $bindable() } = $props();

  let viewerMode = $state("preview");
  const modes = [
    { id: "preview", label: "Preview" },
    { id: "hex", label: "Hex" },
    { id: "strings", label: "Strings" },
    { id: "metadata", label: "Metadata" },
  ];

  const demoRows = [
    { id: 1, sender: "+62812...", message: "Hello!", timestamp: "1780425600" },
    { id: 2, sender: "+62813...", message: "Meeting at 3pm", timestamp: "1780429200" },
    { id: 3, sender: "System", message: "Backup complete", timestamp: "1780432800" },
  ];
</script>

<div class="sqlite-manager">
  <div class="sqlite-header">
    <h3>SQLite Manager</h3>
    <span class="hint">Forensic table browser — WhatsApp, Chrome, iOS backups</span>
  </div>

  {#if !activeCase}
    <div class="empty-state">
      <span class="icon">🗄️</span>
      <p>Open a case and select a SQLite artifact from Sources</p>
    </div>
  {:else}
    <div class="table-wrap">
      <div class="sql-thead">
        <span>id</span><span>sender</span><span>message</span><span>timestamp</span>
      </div>
      {#each demoRows as row}
        <div class="sql-row">
          <span class="mono">{row.id}</span>
          <span class="mono">{row.sender}</span>
          <span>{row.message}</span>
          <span class="mono dim">{row.timestamp}</span>
        </div>
      {/each}
    </div>

    <div class="viewer-panel">
      <SegmentedControl options={modes} bind:value={viewerMode} />
      <div class="viewer-content">
        {#if viewerMode === "preview"}
          <pre class="preview-text">SELECT * FROM messages ORDER BY timestamp DESC LIMIT 100;</pre>
        {:else if viewerMode === "hex"}
          <pre class="mono dim">53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33</pre>
        {:else if viewerMode === "strings"}
          <pre class="preview-text">Hello!\nMeeting at 3pm\nBackup complete</pre>
        {:else}
          <dl class="meta-list">
            <dt>Tables</dt><dd>messages, contacts, media</dd>
            <dt>Pages</dt><dd>128</dd>
            <dt>Encoding</dt><dd>UTF-8</dd>
          </dl>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .sqlite-manager { display: flex; flex-direction: column; height: 100%; gap: 12px; }
  .sqlite-header h3 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
  .hint { font-size: 11px; color: var(--text-muted); }
  .table-wrap {
    flex: 1; min-height: 0; overflow: auto;
    border: 1px solid var(--divider); border-radius: 8px;
    background: rgba(0, 0, 0, 0.15);
  }
  .sql-thead, .sql-row {
    display: grid; grid-template-columns: 48px 1fr 2fr 120px;
    padding: 8px 12px; gap: 8px; font-size: 12px;
    border-bottom: 1px solid var(--divider);
  }
  .sql-thead {
    position: sticky; top: 0; background: rgba(0, 0, 0, 0.35);
    font-weight: 600; color: var(--text-secondary); font-size: 11px;
  }
  .sql-row:hover { background: var(--primary-bg); }
  .viewer-panel {
    flex-shrink: 0; border-top: 1px solid var(--divider);
    padding-top: 10px; display: flex; flex-direction: column; gap: 8px;
  }
  .viewer-content {
    min-height: 100px; max-height: 160px; overflow: auto;
    background: rgba(0, 0, 0, 0.2); border: 1px solid var(--divider);
    border-radius: 8px; padding: 10px 12px;
  }
  .preview-text, .mono { font-family: var(--mono); font-size: 11px; margin: 0; }
  .dim { color: var(--text-muted); }
  .meta-list { margin: 0; font-size: 12px; display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; }
  .meta-list dt { color: var(--text-muted); }
  .meta-list dd { margin: 0; color: var(--text); }
</style>
