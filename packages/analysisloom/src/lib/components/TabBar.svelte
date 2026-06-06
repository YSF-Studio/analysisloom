<script>
  let { tabs = $bindable(), activeView = $bindable(), pinnedIds = ["files"] } = $props();

  let wrapEl = $state(null);
  let showScrollHint = $state(false);

  function selectTab(id) {
    activeView = id;
  }

  function closeTab(id, e) {
    e.stopPropagation();
    if (pinnedIds.includes(id)) return;
    const idx = tabs.findIndex((t) => t.id === id);
    if (idx < 0) return;
    tabs = tabs.filter((t) => t.id !== id);
    if (activeView === id && tabs.length) {
      activeView = tabs[Math.min(idx, tabs.length - 1)].id;
    }
  }

  function isPinned(id) {
    return pinnedIds.includes(id);
  }

  function checkOverflow() {
    if (!wrapEl) return;
    const bar = wrapEl.querySelector(".tab-bar");
    if (!bar) return;
    showScrollHint = bar.scrollWidth > bar.clientWidth + 4;
  }

  $effect(() => {
    tabs;
    activeView;
    queueMicrotask(checkOverflow);
  });
</script>

<svelte:window onresize={checkOverflow} />

<div class="tab-bar-wrap" class:has-overflow={showScrollHint} bind:this={wrapEl}>
  <div class="tab-bar" role="tablist" aria-label="Open documents" onscroll={checkOverflow}>
    {#each tabs as tab (tab.id)}
      <button
        class="tab"
        class:active={activeView === tab.id}
        role="tab"
        aria-selected={activeView === tab.id}
        onclick={() => selectTab(tab.id)}
      >
        <span class="tab-icon" aria-hidden="true">{tab.icon}</span>
        <span class="tab-label">{tab.label}</span>
        {#if !isPinned(tab.id)}
          <span
            class="tab-close"
            role="button"
            tabindex="0"
            aria-label="Close {tab.label}"
            onclick={(e) => closeTab(tab.id, e)}
            onkeydown={(e) => e.key === "Enter" && closeTab(tab.id, e)}
          >✕</span>
        {/if}
      </button>
    {/each}
  </div>
</div>

<style>
  .tab-bar-wrap {
    position: relative;
    flex-shrink: 0;
  }
  .tab-bar-wrap.has-overflow::after {
    content: '';
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 28px;
    background: linear-gradient(to right, transparent, rgba(12, 12, 12, 0.92));
    pointer-events: none;
    z-index: 2;
  }
  :global(html.theme-light) .tab-bar-wrap.has-overflow::after {
    background: linear-gradient(to right, transparent, rgba(245, 245, 247, 0.95));
  }
  .tab-bar {
    display: flex;
    align-items: center;
    gap: 0;
    height: 32px;
    padding: 0 8px;
    background: var(--surface-tabbar);
    border-bottom: 1px solid var(--divider);
    overflow-x: auto;
    scroll-behavior: smooth;
    scrollbar-width: thin;
  }
  .tab-bar::-webkit-scrollbar { height: 3px; }
  .tab-bar::-webkit-scrollbar-thumb { background: var(--divider); border-radius: 2px; }
  .tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    height: 28px;
    border: none;
    border-radius: 6px 6px 0 0;
    background: transparent;
    color: var(--text-muted);
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.12s, color 0.12s;
    flex-shrink: 0;
  }
  .tab:hover { background: var(--surface-tab-hover); color: var(--text-secondary); }
  .tab.active {
    background: var(--surface-tab-active);
    color: var(--text);
    border: 1px solid var(--divider);
    border-bottom-color: transparent;
    box-shadow: inset 0 -2px 0 var(--primary);
  }
  .tab-icon { font-size: 12px; }
  .tab-label { font-size: 12px; }
  .tab-close {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border-radius: 3px;
    font-size: 9px;
    color: var(--text-muted);
    margin-left: 2px;
  }
  .tab-close:hover { background: var(--danger-bg); color: var(--danger); }
</style>
