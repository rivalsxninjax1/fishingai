import { X, Check, FileDown } from 'lucide-react'
import LayerBars from './LayerBars'
import { markFalsePositive } from '../api'

const VERDICT_STYLE = {
  SCAM: { text: 'var(--color-scam-text)' },
  SUSPICIOUS: { text: 'var(--color-suspicious-text)' },
  SAFE: { text: 'var(--color-safe-text)' },
}

export default function ThreatDetail({ threat, onClose, onMarkedSafe }) {
  if (!threat) return null
  const style = VERDICT_STYLE[threat.verdict] || VERDICT_STYLE.SAFE

  const handleMarkSafe = async () => {
    await markFalsePositive(threat.id)
    onMarkedSafe(threat.id)
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-[var(--color-bg-surface)] border border-[var(--color-border)] max-w-xl w-full max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--color-border)]">
          <div>
            <p className="text-[11px] font-mono" style={{ color: style.text }}>
              {threat.verdict} — {threat.risk_score}/100
            </p>
            <p className="text-sm font-medium mt-0.5">{threat.subject}</p>
          </div>
          <X size={18} className="cursor-pointer text-[var(--color-text-muted)]" onClick={onClose} />
        </div>

        <div className="px-5 py-4 space-y-4">
          <div>
            <p className="text-[11px] text-[var(--color-text-muted)] mb-1">From</p>
            <p className="text-[13px] font-mono">{threat.sender}</p>
          </div>

          <div>
            <p className="text-[11px] text-[var(--color-text-muted)] mb-2">Layer breakdown</p>
            <div className="space-y-1.5">
              {Object.entries(threat.layer_scores || {}).map(([layer, data]) => (
                <div key={layer} className="flex items-center gap-2">
                  <span className="text-[11px] text-[var(--color-text-muted)] w-36 truncate">{layer}</span>
                  <div className="flex-1 h-1.5 bg-[var(--color-border)] rounded-full overflow-hidden">
                    <div
                      className="h-full"
                      style={{
                        width: data.max ? `${(data.score / data.max) * 100}%` : '0%',
                        background: data.score / (data.max || 1) >= 0.6 ? 'var(--color-scam)' : 'var(--color-suspicious)'
                      }}
                    />
                  </div>
                  <span className="text-[11px] font-mono w-10 text-right text-[var(--color-text-muted)]">
                    {data.score}/{data.max}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-[11px] text-[var(--color-text-muted)] mb-2">Why flagged</p>
            <ul className="space-y-1">
              {(threat.reasons || []).slice(0, 8).map((reason, i) => (
                <li key={i} className="text-[13px] text-[var(--color-text-primary)] leading-relaxed">
                  {reason}
                </li>
              ))}
            </ul>
          </div>

          <div className="bg-[var(--color-bg-base)] p-3 border border-[var(--color-border)]">
            <p className="text-[11px] text-[var(--color-text-muted)] mb-1">Recommended action</p>
            <p className="text-[13px]">{threat.recommended_action}</p>
          </div>
        </div>

        <div className="flex gap-2 px-5 py-4 border-t border-[var(--color-border)]">
          <button
            onClick={handleMarkSafe}
            className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 border border-[var(--color-border)] hover:border-[var(--color-safe)] transition-colors"
          >
            <Check size={14} /> Mark safe
          </button>
          <button className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 border border-[var(--color-border)] hover:border-[var(--color-text-muted)] transition-colors">
            <FileDown size={14} /> Export PDF
          </button>
        </div>
      </div>
    </div>
  )
}