<script>
  import { invoke } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    caseSealed = false,
  } = $props();

  let bookmarks = $state([]);
  let findings = $state([]);
  let loading = $state(false);
  let showAdd = $state(false);
  let addFilePath = $state("");
  let addTag = $state("");
  let addNote = $state("");
  let reviewerName = $state("Peer Reviewer");
  let reviewNotes = $state({});
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Key Findings & Bookmarks",
      addBookmark: "+ Bookmark",
      cancel: "✕ Cancel",
      sealed: "Case sealed — read-only. Peer review and edits are locked.",
      openCase: "Open a case first from the Case Manager",
      reviewer: "Peer reviewer name",
      filePath: "File Path:",
      tag: "Tag:",
      note: "Note:",
      saveBookmark: "✅ Save Bookmark",
      loading: "Loading...",
      findings: "Findings — Peer Review",
      pending: "pending",
      export: "📤 Export",
      reviewNote: "Review note (optional)",
      approve: "✓ Approve",
      reject: "✕ Reject",
      revise: "↻ Revise",
      reviewedBy: "Reviewed by",
      bookmarks: "Bookmarks",
      noFindings: "No findings yet — add evidence to generate findings.",
      noBookmarks: "No bookmarks yet — add evidence or create a bookmark.",
      filePathPlaceholder: "Evidence file path",
      tagPlaceholder: "suspicious, malware",
      notePlaceholder: "Optional note...",
    },
    id: {
      title: "Temuan Utama & Bookmark",
      addBookmark: "+ Bookmark",
      cancel: "✕ Batal",
      sealed: "Kasus disegel — hanya baca. Review sejawat dan edit terkunci.",
      openCase: "Buka kasus dulu dari Manajer Kasus",
      reviewer: "Nama peninjau sejawat",
      filePath: "Lokasi File:",
      tag: "Tag:",
      note: "Catatan:",
      saveBookmark: "✅ Simpan Bookmark",
      loading: "Memuat...",
      findings: "Temuan — Review Sejawat",
      pending: "menunggu",
      export: "📤 Ekspor",
      reviewNote: "Catatan review (opsional)",
      approve: "✓ Setuju",
      reject: "✕ Tolak",
      revise: "↻ Revisi",
      reviewedBy: "Ditinjau oleh",
      bookmarks: "Bookmark",
      noFindings: "Belum ada temuan — tambahkan bukti untuk membuat temuan.",
      noBookmarks: "Belum ada bookmark — tambahkan bukti atau buat bookmark.",
      filePathPlaceholder: "Path file bukti",
      tagPlaceholder: "mencurigakan, malware",
      notePlaceholder: "Catatan opsional...",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  const isSealed = $derived(caseSealed || activeCase?.status === "sealed");

  async function loadAll() {
    if (!activeCase?.id) {
      bookmarks = [];
      findings = [];
      return;
    }
    loading = true;
    try {
      [bookmarks, findings] = await Promise.all([
        timeoutPromise(invoke("list_bookmarks", { caseId: activeCase.id }), 10000),
        timeoutPromise(invoke("list_findings", { caseId: activeCase.id }), 10000),
      ]);
    } catch {
      bookmarks = [];
      findings = [];
    } finally {
      loading = false;
    }
  }

  async function doAddBookmark() {
    if (!addFilePath || !activeCase?.id || isSealed) return;
    try {
      await invoke("add_bookmark", {
        caseId: activeCase.id,
        filePath: addFilePath,
        offset: 0,
        tag: addTag || null,
        note: addNote || null,
      });
      msg = `✅ Bookmark added: ${addFilePath}`;
      addFilePath = "";
      addTag = "";
      addNote = "";
      showAdd = false;
      await loadAll();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  async function doDeleteBookmark(id) {
    if (isSealed) return;
    try {
      await invoke("delete_bookmark", { id });
      bookmarks = bookmarks.filter((b) => b.id !== id);
      msg = "✅ Bookmark deleted";
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  async function reviewFinding(findingId, status) {
    if (!activeCase?.id || isSealed) return;
    try {
      await invoke("review_finding", {
        findingId,
        status,
        reviewer: reviewerName || activeCase.operator || "Reviewer",
        note: reviewNotes[findingId] || null,
      });
      msg = `✅ Finding #${findingId} → ${status}`;
      await loadAll();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  async function exportBookmark(id) {
    if (!activeCase?.id) return;
    const dest = await save({
      defaultPath: `bookmark_${id}.html`,
      filters: [{ name: "HTML Report", extensions: ["html"] }],
    });
    if (!dest) return;
    try {
      const path = await invoke("export_bookmark", {
        caseId: activeCase.id,
        bookmarkId: id,
        outputPath: dest,
      });
      msg = `✅ Bookmark exported: ${path}`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  async function exportFinding(id) {
    if (!activeCase?.id) return;
    const dest = await save({
      defaultPath: `finding_${id}.html`,
      filters: [{ name: "HTML Report", extensions: ["html"] }],
    });
    if (!dest) return;
    try {
      const path = await invoke("export_finding", {
        caseId: activeCase.id,
        findingId: id,
        outputPath: dest,
      });
      msg = `✅ Finding exported: ${path}`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  function reviewColor(status) {
    if (status === "approved") return "approved";
    if (status === "rejected") return "rejected";
    if (status === "needs_revision") return "revision";
    return "pending";
  }

  $effect(() => {
    loadAll();
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="bookmark-tab">
  <div class="toolbar">
    <h3>🔖 {t("title")}</h3>
    {#if !isSealed}
      <button class="btn-ghost" onclick={() => { showAdd = !showAdd; if (!showAdd) { addFilePath = ""; addTag = ""; addNote = ""; } }}>
        {showAdd ? t("cancel") : t("addBookmark")}
      </button>
    {/if}
  </div>

  {#if isSealed}
    <div class="sealed-banner">🔒 {t("sealed")}</div>
  {/if}

  {#if !activeCase?.id}
    <div class="empty-state">
      <span class="icon">📂</span>
      <p>{t("openCase")}</p>
    </div>
  {:else}
    <div class="reviewer-row">
      <label for="reviewer-name">{t("reviewer")}</label>
      <input id="reviewer-name" type="text" bind:value={reviewerName} disabled={isSealed} />
    </div>

    {#if showAdd && !isSealed}
      <div class="card add-form">
        <div class="row">
          <label for="bookmark-file-path">{t("filePath")}</label>
          <input id="bookmark-file-path" type="text" bind:value={addFilePath} placeholder={t("filePathPlaceholder")} />
        </div>
        <div class="row">
          <label for="bookmark-tag">{t("tag")}</label>
          <input id="bookmark-tag" type="text" bind:value={addTag} placeholder={t("tagPlaceholder")} />
        </div>
        <div class="row">
          <label for="bookmark-note">{t("note")}</label>
          <textarea id="bookmark-note" bind:value={addNote} placeholder={t("notePlaceholder")} rows="2"></textarea>
        </div>
        <button class="btn-primary" onclick={doAddBookmark} disabled={!addFilePath}>{t("saveBookmark")}</button>
      </div>
    {/if}

    {#if loading}
      <div class="loading-state"><span class="spinner">⏳</span> {t("loading")}</div>
    {:else}
      <section class="section">
        <h4>🔍 {t("findings")}</h4>
        {#if findings.length > 0}
          <div class="finding-list">
            {#each findings as f}
              <div class="finding-card {reviewColor(f.reviewStatus || 'pending')}">
                <div class="finding-head">
                  <span class="severity">[{f.severity}]</span>
                  <span class="review-badge">{f.reviewStatus || t("pending")}</span>
                  <button class="btn-export" onclick={() => exportFinding(f.id)}>{t("export")}</button>
                </div>
                <p class="finding-desc">{f.description}</p>
                <span class="finding-file">{f.filePath}</span>
                {#if !isSealed}
                  <input
                    class="review-input"
                    placeholder={t("reviewNote")}
                    bind:value={reviewNotes[f.id]}
                  />
                  <div class="review-actions">
                    <button class="btn-approve" onclick={() => reviewFinding(f.id, "approved")}>{t("approve")}</button>
                    <button class="btn-reject" onclick={() => reviewFinding(f.id, "rejected")}>{t("reject")}</button>
                    <button class="btn-revision" onclick={() => reviewFinding(f.id, "needs_revision")}>{t("revise")}</button>
                  </div>
                {:else if f.reviewer}
                  <span class="review-meta">{t("reviewedBy")} {f.reviewer} — {f.reviewedAt || ""}</span>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <p class="hint">{t("noFindings")}</p>
        {/if}
      </section>

      <section class="section">
        <h4>🔖 {t("bookmarks")}</h4>
        {#if bookmarks.length > 0}
          <div class="bm-list">
            {#each bookmarks as bm}
              <div class="bm-card">
                <div class="bm-header">
                  <span class="bm-file" title={bm.filePath}>{bm.filePath}</span>
                  <div class="bm-actions">
                    <button class="btn-export" onclick={() => exportBookmark(bm.id)}>📤</button>
                    {#if !isSealed}
                      <button class="btn-delete" onclick={() => doDeleteBookmark(bm.id)}>✕</button>
                    {/if}
                  </div>
                </div>
                <div class="bm-meta">
                  {#if bm.tag}<span class="bm-tag">{bm.tag}</span>{/if}
                </div>
                {#if bm.note}<p class="bm-note">{bm.note}</p>{/if}
              </div>
            {/each}
          </div>
        {:else}
          <p class="hint">{t("noBookmarks")}</p>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<style>
  .bookmark-tab { display: flex; flex-direction: column; height: 100%; overflow-y: auto; }
  .toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .toolbar h3 { margin: 0; font-size: 16px; }
  .sealed-banner {
    background: rgba(245,158,11,0.12); border: 1px solid var(--warn, #f59e0b);
    color: var(--warn, #f59e0b); padding: 8px 12px; border-radius: 8px;
    font-size: 12px; margin-bottom: 12px;
  }
  .reviewer-row { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 12px; }
  .reviewer-row label { color: var(--text-muted); white-space: nowrap; }
  .reviewer-row input { flex: 1; font-size: 12px; padding: 4px 8px; }
  .section { margin-bottom: 20px; }
  .section h4 { margin: 0 0 8px; font-size: 13px; color: var(--text-secondary); }
  .hint { font-size: 12px; color: var(--text-muted); }
  .btn-ghost { padding: 6px 14px; background: transparent; border: 1px solid var(--border); border-radius: 6px; color: var(--text-secondary); cursor: pointer; font-size: 12px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; margin-bottom: 12px; }
  .add-form .row { margin-bottom: 8px; }
  .add-form label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 4px; }
  .add-form input, .add-form textarea { width: 100%; box-sizing: border-box; font-size: 12px; padding: 6px 8px; }
  .btn-primary { padding: 8px 16px; background: var(--primary); color: var(--text-on-primary); border: none; border-radius: 8px; font-size: 12px; cursor: pointer; }
  .finding-list, .bm-list { display: flex; flex-direction: column; gap: 8px; }
  .finding-card, .bm-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
  }
  .finding-card.approved { border-left: 3px solid var(--success, #22c55e); }
  .finding-card.rejected { border-left: 3px solid var(--danger, #ef4444); }
  .finding-card.revision { border-left: 3px solid var(--warn, #f59e0b); }
  .finding-card.pending { border-left: 3px solid var(--text-muted); }
  .finding-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .severity { font-size: 11px; font-weight: 600; color: var(--primary); }
  .review-badge { font-size: 10px; padding: 2px 8px; border-radius: 10px; background: var(--surface-subtle); color: var(--text-secondary); text-transform: uppercase; }
  .finding-desc { font-size: 12px; margin: 4px 0; color: var(--text); }
  .finding-file { font-size: 10px; font-family: var(--mono); color: var(--text-muted); word-break: break-all; }
  .review-input { width: 100%; margin-top: 6px; font-size: 11px; padding: 4px 8px; box-sizing: border-box; }
  .review-actions { display: flex; gap: 6px; margin-top: 6px; }
  .btn-approve, .btn-reject, .btn-revision, .btn-export {
    padding: 4px 10px; border-radius: 6px; font-size: 10px; font-weight: 600; cursor: pointer; border: 1px solid var(--border);
  }
  .btn-approve { background: rgba(34,197,94,0.12); color: var(--success); }
  .btn-reject { background: rgba(239,68,68,0.12); color: var(--danger); }
  .btn-revision { background: rgba(245,158,11,0.12); color: var(--warn); }
  .btn-export { background: transparent; color: var(--primary); }
  .review-meta { font-size: 10px; color: var(--text-muted); display: block; margin-top: 4px; }
  .bm-header { display: flex; justify-content: space-between; gap: 8px; }
  .bm-file { font-family: var(--mono); font-size: 11px; flex: 1; overflow: hidden; text-overflow: ellipsis; }
  .bm-actions { display: flex; gap: 4px; }
  .btn-delete { background: transparent; border: none; color: var(--text-muted); cursor: pointer; }
  .bm-tag { font-size: 10px; padding: 1px 6px; border-radius: 8px; background: var(--primary-bg); color: var(--primary); }
  .bm-note { font-size: 11px; color: var(--text-secondary); margin: 4px 0 0; }
  .empty-state, .loading-state { display: flex; flex-direction: column; align-items: center; padding: 40px; color: var(--text-muted); font-size: 13px; }
  .spinner { animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
