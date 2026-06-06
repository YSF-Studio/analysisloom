<script>
  let { sources = $bindable(), selectedSource = $bindable(), onSelect } = $props();

  let expanded = $state({});

  $effect(() => {
    for (const src of sources) {
      if (expanded[src.id] === undefined) expanded[src.id] = true;
    }
  });

  function toggle(id) {
    expanded[id] = !expanded[id];
  }

  function pick(source) {
    selectedSource = source;
    onSelect?.(source);
  }
</script>

<div class="source-tree">
  {#each sources as src}
    <div class="source-group">
      <button class="source-root" onclick={() => toggle(src.id)}>
        <span class="chevron" class:open={expanded[src.id]}>›</span>
        <span class="icon">{src.icon}</span>
        <span class="label">{src.name}</span>
      </button>
      {#if expanded[src.id]}
        <div class="source-children">
          {#each src.children || [] as child}
            <button
              class="source-child"
              class:active={selectedSource?.id === child.id}
              onclick={() => pick(child)}
            >
              <span class="icon">{child.icon}</span>
              <span>{child.name}</span>
            </button>
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .source-tree { padding: 2px 8px 8px; }
  .source-root, .source-child {
    display: flex; align-items: center; gap: 6px;
    width: 100%; padding: 5px 8px; border: none; border-radius: 6px;
    background: transparent; color: var(--text-secondary);
    font-size: 12px; text-align: left; cursor: pointer;
  }
  .source-root:hover, .source-child:hover {
    background: rgba(255, 255, 255, 0.04); color: var(--text);
  }
  .source-child.active {
    background: var(--primary-bg); color: var(--primary); font-weight: 600;
  }
  .source-children { padding-left: 18px; }
  .chevron {
    display: inline-block; width: 10px; font-size: 11px;
    transition: transform 0.12s; color: var(--text-muted);
  }
  .chevron.open { transform: rotate(90deg); }
  .icon { width: 16px; text-align: center; flex-shrink: 0; }
  .label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
