<script>
  let { sources = $bindable(), selectedSource = $bindable(), onSelect, onAddImage, loading = false } = $props();

  let expanded = $state({});

  $effect(() => {
    for (const src of sources) {
      if (expanded[src.id] === undefined) expanded[src.id] = true;
      walk(src.children || [], (node) => {
        if (expanded[node.id] === undefined) expanded[node.id] = false;
      });
    }
  });

  function walk(nodes, fn) {
    for (const n of nodes) {
      fn(n);
      if (n.children?.length) walk(n.children, fn);
    }
  }

  function toggle(id) {
    expanded[id] = !expanded[id];
  }

  function pick(source) {
    selectedSource = source;
    onSelect?.(source);
  }
</script>

<div class="source-tree">
  <button class="add-source" onclick={() => onAddImage?.()} disabled={loading}>
    {loading ? "⏳ Loading…" : "+ Add Image"}
  </button>

  {#each sources as src}
    <div class="source-group">
      <button class="source-root" onclick={() => toggle(src.id)}>
        <span class="chevron" class:open={expanded[src.id]}>›</span>
        <span class="icon">{src.icon}</span>
        <span class="label" title={src.name}>{src.name}</span>
        {#if src.entryCount}<span class="badge">{src.entryCount}</span>{/if}
      </button>
      {#if expanded[src.id]}
        <div class="source-children">
          <button
            class="source-child"
            class:active={selectedSource?.id === `${src.id}-root`}
            onclick={() => pick({ id: `${src.id}-root`, imageId: src.id, recordNumber: 5, name: src.name, isRoot: true })}
          >
            <span class="icon">🌐</span>
            <span>\ (root)</span>
          </button>
          {#each src.children || [] as child}
            {@render treeNode(child, src.id)}
          {/each}
        </div>
      {/if}
    </div>
  {/each}

  {#if !sources.length}
    <p class="hint">Add a disk image to browse NTFS sources</p>
  {/if}
</div>

{#snippet treeNode(node, imageId)}
  <div class="tree-node">
    <button
      class="source-child"
      class:active={selectedSource?.id === node.id}
      onclick={() => pick({ ...node, imageId })}
    >
      {#if node.children?.length}
        <span
          class="chevron small"
          class:open={expanded[node.id]}
          onclick={(e) => { e.stopPropagation(); toggle(node.id); }}
          role="button"
          tabindex="0"
        >›</span>
      {:else}
        <span class="chevron-spacer"></span>
      {/if}
      <span class="icon">{node.icon}</span>
      <span class="node-name">{node.name}</span>
    </button>
    {#if node.children?.length && expanded[node.id]}
      <div class="nested">
        {#each node.children as child}
          {@render treeNode(child, imageId)}
        {/each}
      </div>
    {/if}
  </div>
{/snippet}

<style>
  .source-tree { padding: 2px 8px 8px; }
  .add-source {
    width: calc(100% - 8px); margin: 4px 4px 8px; padding: 6px 10px;
    border: 1px dashed var(--divider); border-radius: 6px;
    background: transparent; color: var(--primary); font-size: 11px;
    font-weight: 600; cursor: pointer;
  }
  .add-source:hover:not(:disabled) { background: var(--primary-bg); }
  .add-source:disabled { opacity: 0.5; cursor: default; }
  .hint { font-size: 11px; color: var(--text-muted); padding: 4px 10px; margin: 0; }
  .source-root, .source-child {
    display: flex; align-items: center; gap: 6px;
    width: 100%; padding: 5px 8px; border: none; border-radius: 6px;
    background: transparent; color: var(--text-secondary);
    font-size: 12px; text-align: left; cursor: pointer;
  }
  .source-root:hover, .source-child:hover {
    background: var(--surface-subtle); color: var(--text);
  }
  .source-child.active {
    background: var(--primary-bg); color: var(--primary); font-weight: 600;
  }
  .source-children { padding-left: 6px; }
  .nested { padding-left: 14px; }
  .chevron {
    display: inline-block; width: 10px; font-size: 11px;
    transition: transform 0.12s; color: var(--text-muted); flex-shrink: 0;
  }
  .chevron.small { width: 8px; font-size: 10px; }
  .chevron.open { transform: rotate(90deg); }
  .chevron-spacer { width: 8px; flex-shrink: 0; }
  .icon { width: 16px; text-align: center; flex-shrink: 0; }
  .label, .node-name {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;
  }
  .badge {
    font-size: 9px; padding: 1px 5px; border-radius: 8px;
    background: var(--surface-muted); color: var(--text-muted);
  }
</style>
