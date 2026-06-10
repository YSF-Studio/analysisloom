<script>
  import { invoke } from "@tauri-apps/api/core";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let {
    metadata,
    filename = "",
    visible,
    note = $bindable(""),
    tags = $bindable(""),
    hashLoading = false,
    integrityStatus = null,
    caseId = null,
    selectedFile = "",
    caseSealed = false,
    onAddEvidence,
    onOpenArtifact,
    onNoteSaved,
  } = $props();

  let hashAlgo = $state("sha256");
  let caseNoteDraft = $state("");
  let caseNotes = $state([]);
  let savingNote = $state(false);
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      selectedFile: "Selected file",
      hash: "Hash",
      computingHash: "Computing hash…",
      mftOnly: "MFT metadata only — open local/carved copy to hash",
      verified: "✓ Integrity verified (manifest)",
      integrityFail: "✗ INTEGRITY FAIL — hash mismatch",
      noManifest: "⚠ No acquisition manifest — hash not verified against source",
      caseSealed: "🔒 Case Sealed",
      addToEvidence: "Add to Evidence ↗",
      openLocalCopy: "Open Local Copy…",
      quickLook: "Quick Look",
      size: "Size",
      modified: "Modified",
      entropy: "Entropy",
      magic: "Magic",
      mftNumber: "MFT #",
      links: "Links",
      linkHint: "Link related artifacts after carving",
      bookmarkNote: "Bookmark Note",
      notePlaceholder: "Note saved with bookmark/evidence...",
      tags: "Tags",
      caseLog: "Case Analysis Log",
      caseLogPlaceholder: "Document observations during examination...",
      saveCaseLog: "Save to Case Log",
      saving: "Saving…",
      selectFile: "Select a file for Quick Look & evidence linking",
      low: "Low",
      medium: "Medium",
      high: "High",
    },
    id: {
      selectedFile: "File terpilih",
      hash: "Hash",
      computingHash: "Menghitung hash…",
      mftOnly: "Hanya metadata MFT — buka salinan lokal/carved untuk hash",
      verified: "✓ Integritas terverifikasi (manifest)",
      integrityFail: "✗ GAGAL INTEGRITAS — hash tidak cocok",
      noManifest: "⚠ Tidak ada manifest akuisisi — hash belum diverifikasi terhadap sumber",
      caseSealed: "🔒 Kasus Disegel",
      addToEvidence: "Tambahkan ke Bukti ↗",
      openLocalCopy: "Buka Salinan Lokal…",
      quickLook: "Pratinjau Cepat",
      size: "Ukuran",
      modified: "Diubah",
      entropy: "Entropi",
      magic: "Magic",
      mftNumber: "MFT #",
      links: "Tautan",
      linkHint: "Tautkan artefak terkait setelah carving",
      bookmarkNote: "Catatan Bookmark",
      notePlaceholder: "Catatan disimpan bersama bookmark/bukti...",
      tags: "Tag",
      caseLog: "Log Analisis Kasus",
      caseLogPlaceholder: "Dokumentasikan pengamatan selama pemeriksaan...",
      saveCaseLog: "Simpan ke Log Kasus",
      saving: "Menyimpan…",
      selectFile: "Pilih file untuk Quick Look & penautan bukti",
      low: "Rendah",
      medium: "Sedang",
      high: "Tinggi",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  function entropyLabel(e) {
    if (e == null) return "—";
    if (e < 4.0) return t("low");
    if (e < 6.5) return t("medium");
    return t("high");
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

  async function loadCaseNotes() {
    if (!caseId) {
      caseNotes = [];
      return;
    }
    try {
      caseNotes = await invoke("list_case_notes", { caseId });
    } catch {
      caseNotes = [];
    }
  }

  async function saveCaseNote() {
    if (!caseId || !caseNoteDraft.trim()) return;
    savingNote = true;
    try {
      await invoke("append_case_note", {
        caseId,
        body: caseNoteDraft.trim(),
        filePath: selectedFile || null,
      });
      caseNoteDraft = "";
      await loadCaseNotes();
      onNoteSaved?.();
      } catch (e) {
      console.error("Failed to save case note:", e);
      caseNotes = caseNotes || [];
      caseNoteDraft = caseNoteDraft || "";
    } finally {
      savingNote = false;
    }
  }

  $effect(() => {
    if (caseId) loadCaseNotes();
    else {
      caseNotes = [];
      caseNoteDraft = "";
    }
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

{#if visible}
  <div class="inspector">
    {#if metadata || filename}
      <div class="file-header">
        <span class="file-icon">📄</span>
        <span class="file-name">{filename || t("selectedFile")}</span>
      </div>

      <section class="form-section">
        <div class="hash-head">
          <span class="field-label">{t("hash")}</span>
          <div class="hash-tabs">
            <button class="htab" class:active={hashAlgo === "sha256"} onclick={() => hashAlgo = "sha256"}>SHA-256</button>
            <button class="htab" class:active={hashAlgo === "sha1"} onclick={() => hashAlgo = "sha1"}>SHA-1</button>
            <button class="htab" class:active={hashAlgo === "md5"} onclick={() => hashAlgo = "md5"}>MD5</button>
          </div>
        </div>
        <div class="hash-box mono">
          {#if hashLoading}
            <span class="dim">{t("computingHash")}</span>
          {:else if hasHash}
            {hash}
          {:else if metadata?.source === "mft"}
            <span class="dim">{t("mftOnly")}</span>
          {:else}
            —
          {/if}
        </div>
        {#if integrityStatus}
          <div class="integrity" class:pass={integrityStatus.verified} class:fail={!integrityStatus.verified && integrityStatus.expectedSha256} class:warn={!integrityStatus.expectedSha256}>
            {#if integrityStatus.expectedSha256}
              {integrityStatus.verified ? t("verified") : t("integrityFail")}
            {:else}
              {t("noManifest")}
            {/if}
          </div>
        {/if}
      </section>

      <section class="form-section">
        <button class="btn-evidence" onclick={() => onAddEvidence?.()} disabled={caseSealed}>
          {caseSealed ? t("caseSealed") : t("addToEvidence")}
        </button>
        {#if metadata?.source === "mft"}
          <button class="btn-artifact" onclick={() => onOpenArtifact?.()}>
            {t("openLocalCopy")}
          </button>
        {/if}
      </section>

      {#if metadata}
        <section class="form-section">
          <span class="field-label">{t("quickLook")}</span>
          <div class="kv">
            <span>{t("size")}</span><span>{sizeStr(metadata.size)}</span>
            <span>{t("modified")}</span><span class="mono">{metadata.modified}</span>
            <span>{t("entropy")}</span>
            <span>{metadata.entropy != null ? `${metadata.entropy.toFixed(2)} (${entropyLabel(metadata.entropy)})` : "—"}</span>
            {#if metadata.magicMatch}
              <span>{t("magic")}</span><span>{metadata.magicMatch}</span>
            {/if}
            {#if metadata.recordNumber != null}
              <span>{t("mftNumber")}</span><span class="mono">{metadata.recordNumber}</span>
            {/if}
          </div>
        </section>
      {/if}

      <section class="form-section">
        <span class="field-label">{t("links")}</span>
        <div class="links">
          <span class="link-chip dim-chip" aria-disabled="true">{t("linkHint")}</span>
        </div>
      </section>

      <section class="form-section grow">
        <label class="field-label" for="inspector-note">{t("bookmarkNote")}</label>
        <textarea
          id="inspector-note"
          class="note-field"
          bind:value={note}
          placeholder={t("notePlaceholder")}
          rows="3"
        ></textarea>
      </section>

      <section class="form-section">
        <label class="field-label" for="inspector-tags">{t("tags")}</label>
        <input id="inspector-tags" class="tag-field" bind:value={tags} placeholder={locale === "id" ? "malware, PII, exfiltration" : "malware, PII, exfiltration"} />
      </section>

      {#if caseId}
        <section class="form-section case-log">
          <span class="field-label">{t("caseLog")}</span>
          <textarea
            class="note-field"
            bind:value={caseNoteDraft}
            placeholder={t("caseLogPlaceholder")}
            rows="3"
          ></textarea>
          <button class="btn-save-note" onclick={saveCaseNote} disabled={caseSealed || savingNote || !caseNoteDraft.trim()}>
            {savingNote ? t("saving") : t("saveCaseLog")}
          </button>
          {#if caseNotes.length > 0}
            <div class="note-history">
              {#each caseNotes.slice(-5).reverse() as n}
                <div class="note-entry">
                  <span class="note-ts">{n.timestamp}</span>
                  <span class="note-body">{n.body}</span>
                </div>
              {/each}
            </div>
          {/if}
        </section>
      {/if}
    {:else}
      <div class="empty">
        <p>{t("selectFile")}</p>
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
    background: var(--surface-muted); border: 1px solid var(--divider);
    border-radius: 6px; padding: 8px 10px; word-break: break-all;
  }
  .integrity {
    margin-top: 6px; font-size: 10px; font-weight: 600;
    padding: 6px 8px; border-radius: 6px;
  }
  .integrity.pass { background: rgba(34,197,94,0.12); color: var(--success, #22c55e); }
  .integrity.fail { background: rgba(239,68,68,0.12); color: var(--danger, #ef4444); }
  .integrity.warn { background: rgba(245,158,11,0.12); color: var(--warn, #f59e0b); }
  .btn-evidence, .btn-artifact {
    width: 100%; padding: 8px 12px; border-radius: 8px;
    font-size: 12px; font-weight: 600; cursor: pointer;
  }
  .btn-evidence {
    background: var(--primary-bg); border: 1px solid var(--primary);
    color: var(--primary); margin-bottom: 6px;
  }
  .btn-evidence:hover:not(:disabled) { background: var(--primary-hover); }
  .btn-evidence:disabled { opacity: 0.5; cursor: not-allowed; }
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
    background: var(--surface-subtle); border: 1px solid var(--divider);
    color: var(--text-secondary); font-size: 11px; cursor: pointer;
  }
  .dim-chip { cursor: default; opacity: 0.7; }
  .note-field, .tag-field {
    width: 100%; background: var(--surface-inset);
    border: 1px solid var(--divider); border-radius: 8px;
    color: var(--text); font-size: 12px; resize: vertical;
  }
  .note-field { min-height: 56px; font-family: var(--font); }
  .tag-field { padding: 6px 10px; }
  .btn-save-note {
    margin-top: 6px; width: 100%; padding: 6px 10px;
    background: var(--primary-bg); border: 1px solid var(--primary);
    color: var(--primary); border-radius: 6px; font-size: 11px;
    font-weight: 600; cursor: pointer;
  }
  .btn-save-note:disabled { opacity: 0.4; cursor: not-allowed; }
  .note-history { margin-top: 8px; max-height: 120px; overflow-y: auto; }
  .note-entry {
    font-size: 10px; padding: 4px 0; border-bottom: 1px solid var(--divider);
  }
  .note-ts { color: var(--text-muted); display: block; font-family: var(--mono); }
  .note-body { color: var(--text-secondary); }
  .empty {
    display: flex; align-items: center; justify-content: center;
    flex: 1; padding: 24px; text-align: center;
    color: var(--text-muted); font-size: 12px;
  }
</style>
