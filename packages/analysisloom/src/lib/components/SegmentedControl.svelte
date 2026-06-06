<script>
  let { options, value = $bindable(), onchange } = $props();
</script>

<div class="segmented" role="tablist">
  {#each options as opt}
    <button
      type="button"
      role="tab"
      class="segment"
      class:active={value === opt.id}
      aria-selected={value === opt.id}
      onclick={() => { value = opt.id; onchange?.(opt.id); }}
    >{opt.label}</button>
  {/each}
</div>

<style>
  .segmented {
    display: inline-flex;
    background: var(--surface-subtle);
    border: 1px solid var(--divider);
    border-radius: 7px;
    padding: 2px;
    gap: 1px;
  }
  .segment {
    padding: 4px 14px;
    border: none;
    border-radius: 5px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.12s;
    white-space: nowrap;
  }
  .segment:hover { color: var(--text); }
  .segment.active {
    background: var(--primary);
    color: var(--text-on-primary);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15);
    font-weight: 600;
  }
</style>
