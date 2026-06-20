export default function StatusDot({ label, ok }) {
  return (
    <div className="flex items-center gap-1.5">
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: ok ? 'var(--color-safe)' : 'var(--color-scam)' }}
      />
      <span className="text-[11px] font-mono text-[var(--color-text-muted)]">
        {label}
      </span>
    </div>
  )
}