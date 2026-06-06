<script>
  let { severity = "info", label = "" } = $props();

  const normalized = $derived((severity || "info").toLowerCase());
  const display = $derived.by(() => {
    if (label) return label;
    if (normalized === "critical") return "Critical";
    if (normalized === "high") return "High";
    if (normalized === "medium") return "Medium";
    if (normalized === "low") return "Low";
    return "Info";
  });
  const icon = $derived(
    normalized === "critical" ? "🔴" : normalized === "high" || normalized === "medium" ? "🟡" : "🔵"
  );
</script>

<span class="pill-badge pill-{normalized === 'critical' ? 'critical' : normalized === 'high' || normalized === 'medium' ? 'high' : 'info'}">
  {icon} {display}
</span>
