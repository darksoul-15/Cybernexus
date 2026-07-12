export function StatCard({ label, value, accent, sub }: { label: string; value: string | number; accent?: string; sub?: string }) {
  return (
    <div className="card stat-card">
      <div className="stat-value" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub muted">{sub}</div>}
    </div>
  );
}
