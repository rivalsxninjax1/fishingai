export default function StatCard({ label, value, color = 'var(--color-text-primary)' }) {
  return (
    <div className="bg-[var(--color-bg-surface)] px-[18px] py-3.5">
      <p className="text-[11px] text-[var(--color-text-muted)] mb-1">{label}</p>
      <p
        className="text-[22px] font-mono font-medium"
        style={{ color }}
      >
        {value}
      </p>
    </div>
  )
}