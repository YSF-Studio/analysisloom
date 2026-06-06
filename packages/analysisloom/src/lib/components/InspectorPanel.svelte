<script>
  let {
    metadata,
    filename = "",
    visible,
    note = $bindable(""),
    tags = $bindable(""),
    hashLoading = false,
    onAddEvidence,
    onOpenArtifact,
  } = $props();

  let hashAlgo = $state("sha256");

  function entropyLabel(e) {
    if (e == null) return "—";
    if (e < 4.0) return "Low";
    if (e < 6.5) return "Medium";
    return "High";
  }

  function sizeStr(bytes) {
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let i = 0; let s = bytes;
    while (s >= 1024 && i < units.length - 1) { s /= 1024; i++; }
    return `${s.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  const hash = $derived.by(() => {
    if (!metadata) return "—";
    if (hashAlgo === "md5") return metadata.md5 || "—";
    if (hashAlgo === "sha1") return metadata.sha1 || "—";
    return metadata.sha256 || metadata.sha1 || metadata.md5 || "—";
  });

  const hasHash = $derived(
    !!(metadata?.sha256 || metadata?.sha1 || metadata?.md5)
  );
</script>

{#if visible}
  <div class="inspector">
    {#if metadata || filename}
      <div class="file-header">
        <span class="file-icon">📄</span>
        <span class="file-name">{filename || "Selected file"}</span>
      </div>

      <section class="form-section">
        <div class="hash-head">
          <label class="field-label">Hash</label>
          <div class="hash-tabs">
            <button class="htab" class:active={hashAlgo === "sha256"} onclick={() => hashAlgo = "sha256"}>SHA-256</button>
            <button class="htab" class:active={hashAlgo === "sha1"} onclick={() => hashAlgo = "sha1"}>SHA-1</button>
            <button class="htab" class:active={hashAlgo === "md5"} onclick={() => hashAlgo = "md5"}>MD5</button>
          </div>
        </div>
        <div class="hash-box mono">
          {#if hashLoading}
            <span class="dim">Computing hash…</span>
          {:else if hasHash}
            {hash}
          {:else if metadata?.source === "mft"}
            <span class="dim">MFT metadata only — open local/carved copy to hash</span>
          {:else}
            —
          {/if}
        </div>
      </section>

      <section class="form-section">
        <button class="btn-evidence" onclick={() => onAddEvidence?.()}>
          Add to Evidence ↗
        </button>
        {#if metadata?.source === "mft"}
          <button class="btn-artifact" onclick={() => onOpenArtifact?.()}>
            Open Local Copy…
          </button>
        {/if}
      </section>

      {#if metadata}
        <section class="form-section">
          <span class="field-label">Quick Look</span>
          <div class="kv">
            <span>Size</span><span>{sizeStr(metadata.size)}</span>
            <span>Modified</span><span class="mono">{metadata.modified}</span>
            <span>Entropy</span>
            <span>{metadata.entropy != null ? `${metadata.entropy.toFixed(2)} (${entropyLabel(metadata.entropy)})` : "—"}</span>
            {#if metadata.magicMatch}
              <span>Magic</span><span>{metadata.magicMatch}</span>
            {/if}
            {#if metadata.recordNumber != null}
              <span>MFT #</span><span class="mono">{metadata.recordNumber}</span>
            {/if}
          </div>
        </section>
      {/if}

      <section class="form-section">
        <span class="field-label">Links</span>
        <div class="links">
          <button class="link-chip dim-chip">Link related artifacts after carving</button>
        </div>
      </section>

      <section class="form-section grow">
        <label class="field-label" for="inspector-note">Notes</label>
        <textarea
          id="inspector-note"
          class="note-field"
          bind:value={note}
          placeholder="Suspect chat DB..."
          rows="4"
        ></textarea>
      </section>

      <section class="form-section">
        <label class="field-label" for="inspector-tags">Tags</label>
        <input id="inspector-tags" class="tag-field" bind:value={tags} placeholder="malware, PII, exfiltration" />
      </section>
    {:else}
      <div class="empty">
        <p>Select a file for Quick Look &amp; evidence linking</p>
      </div>
    {/if}
  </div>
{/if}

<style>
  .inspector {
    flex: 1; display: flex; flex-direction: column;
    overflow-y: auto; padding: 0 0 12px;
  }
  .file-header {
    display: flex; align-items: center; gap: 8px;
    padding: 12px 14px; border-bottom: 1px solid var(--divider);
  }
  .file-icon { font-size: 18px; }
  .file-name {
    font-size: 13px; font-weight: 600; color: var(--text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .form-section {
    padding: 10px 14px;
    border-bottom: 1px solid var(--divider);
  }
  .form-section.grow { flex: 1; }
  .field-label {
    display: block; font-size: 11px; font-weight: 600;
    color: var(--text-muted); margin-bottom: 6px;
    text-transform: uppercase; letter-spacing: 0.4px;
  }
  .hash-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .hash-head .field-label { margin: 0; }
  .hash-tabs { display: flex; gap: 2px; }
  .htab {
    padding: 2px 6px; border: none; border-radius: 4px;
    background: transparent; color: var(--text-muted);
    font-size: 9px; cursor: pointer;
  }
  .htab.active { background: var(--primary-bg); color: var(--primary); }
  .hash-box {
    font-size: 10px; color: var(--text-secondary);
    background: rgba(0, 0, 0, 0.25); border: 1px solid var(--divider);
    border-radius: 6px; padding: 8px 10px; word-break: break-all;
  }
  .btn-evidence, .btn-artifact {
    width: 100%; padding: 8px 12px; border-radius: 8px;
    font-size: 12px; font-weight: 600; cursor: pointer;
  }
  .btn-evidence {
    background: var(--primary-bg); border: 1px solid var(--primary);
    color: var(--primary); margin-bottom: 6px;
  }
  .btn-evidence:hover { background: var(--primary-hover); }
  .btn-artifact {
    background: transparent; border: 1px solid var(--divider);
    color: var(--text-secondary);
  }
  .btn-artifact:hover { border-color: var(--primary); color: var(--primary); }
  .kv {
    display: grid; grid-template-columns: auto 1fr; gap: 4px 10px;
    font-size: 11px;
  }
  .kv span:nth-child(odd) { color: var(--text-muted); }
  .mono { font-family: var(--mono); }
  .dim { color: var(--text-muted); }
  .links { display: flex; flex-wrap: wrap; gap: 6px; }
  .link-chip {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 4px 10px; border-radius: 14px;
    background: rgba(255, 255, 255, 0.05); border: 1px solid var(--divider);
    color: var(--text-secondary); font-size: 11px; cursor: pointer;
  }
  .dim-chip { cursor: default; opacity: 0.7; }
  .note-field, .tag-field {
    width: 100%; background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--divider); border-radius: 8px;
    color: var(--text); font-size: 12px; resize: vertical;
  }
  .note-field { min-height: 72px; font-family: var(--font); }
  .tag-field { padding: 6px 10px; }
  .empty {
    display: flex; align-items: center; justify-content: center;
    flex: 1; padding: 24px; text-align: center;
    color: var(--text-muted); font-size: 12px;
  }
</style>
