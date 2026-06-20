import LayerBars from './LayerBars'

const VERDICT_STYLE = {
  SCAM: { bg: 'var(--color-scam-bg)', text: 'var(--color-scam-text)', border: 'var(--color-scam)', label: 'SCAM' },
  SUSPICIOUS: { bg: 'var(--color-suspicious-bg)', text: 'var(--color-suspicious-text)', border: 'var(--color-suspicious)', label: 'SUSP' },
  SAFE: { bg: 'var(--color-safe-bg)', text: 'var(--color-safe-text)', border: 'var(--color-safe)', label: 'SAFE' },
}

function timeAgo(dateStr) {
  const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function ThreatRow({ threat, onClick, isNew }) {
  const style = VERDICT_STYLE[threat.verdict] || VERDICT_STYLE.SAFE

  return (
    <div
      onClick={onClick}
      className={`flex items-center gap-3 px-3 py-2.5 bg-[var(--color-bg-surface)] cursor-pointer hover:brightness-110 transition-all ${isNew ? 'animate-pulse' : ''}`}
      style={{
        borderLeft: `2px solid ${style.border}`,
        animation: isNew ? 'slideIn 0.4s ease-out' : 'none'
      }}
    >
      <span
        className="text-[10px] font-medium font-mono px-1.5 py-0.5 tracking-wide rounded-[3px]"
        style={{ background: style.bg, color: style.text }}
      >
        {style.label}
      </span>
      <span className="text-[13px] flex-1 min-w-0 truncate text-[var(--color-text-primary)]">
        {threat.subject || '(no subject)'}
      </span>
      <span
        className="text-[13px] font-mono w-8 text-right"
        style={{ color: style.text }}
      >
        {threat.risk_score}
      </span>
      <span className="text-[11px] text-[var(--color-text-muted)] w-14 text-right">
        {timeAgo(threat.analyzed_at)}
      </span>
    </div>
  )
}