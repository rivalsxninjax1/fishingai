import { AlertTriangle, ShieldCheck } from 'lucide-react'

function timeAgo(dateStr) {
  const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000)
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function AttentionCard({ state, onViewDetails, onHandled }) {
  if (!state) return null

  if (state.status === 'all_clear') {
    return (
      <div className="px-5 pt-7 pb-5">
        <div className="flex items-center gap-2.5 mb-4">
          <ShieldCheck size={20} color="var(--color-safe)" />
          <p className="text-[14px] text-[var(--color-text-primary)]">Your inbox is safe</p>
        </div>
        <div className="flex gap-6 px-1">
          <div>
            <p className="text-[10px] text-[var(--color-text-muted)] mb-0.5">scanned today</p>
            <p className="text-[16px] font-mono text-[var(--color-text-primary)]">{state.scanned_today}</p>
          </div>
          <div>
            <p className="text-[10px] text-[var(--color-text-muted)] mb-0.5">last threat blocked</p>
            <p className="text-[16px] font-mono text-[var(--color-text-primary)]">{state.last_threat_blocked}</p>
          </div>
        </div>
      </div>
    )
  }

  const { threat } = state

  return (
    <div className="px-5 pt-7 pb-5">
      <div
        className="p-[18px_20px] mb-3.5"
        style={{
          background: '#1F1418',
          border: '1px solid #5A2A2D',
          borderLeft: '3px solid var(--color-scam)',
        }}
      >
        <div className="flex items-center gap-2 mb-2.5">
          <AlertTriangle size={18} color="var(--color-scam)" />
          <p className="text-[13px] font-medium tracking-wide" style={{ color: 'var(--color-scam-text)' }}>
            {state.attention_count} EMAIL{state.attention_count > 1 ? 'S' : ''} NEED{state.attention_count === 1 ? 'S' : ''} YOUR ATTENTION
          </p>
        </div>
        <p className="text-[15px] text-[var(--color-text-primary)] mb-1">
          "{threat.subject}"
        </p>
        <p className="text-[12px] font-mono text-[var(--color-text-muted)] mb-4">
          Risk {threat.risk_score}/100 · {threat.top_reason?.replace(/[🚨⚠️]/g, '').trim()} · {timeAgo(threat.analyzed_at)}
        </p>
        <div className="flex gap-2">
          <button
            onClick={() => onViewDetails(threat.id)}
            className="text-[12px] font-medium px-4 py-2 rounded-[3px]"
            style={{ background: 'var(--color-scam)', color: '#1F1418', border: 'none' }}
          >
            View details
          </button>
          <button
            onClick={() => onHandled(threat.id)}
            className="text-[12px] px-4 py-2 rounded-[3px]"
            style={{ background: 'transparent', border: '0.5px solid #5A2A2D', color: 'var(--color-scam-text)' }}
          >
            I'll handle it
          </button>
        </div>
      </div>
      <div className="flex items-center justify-between px-1">
        <p className="text-[11px] text-[var(--color-text-muted)]">Everything else is quiet right now</p>
      </div>
    </div>
  )
}