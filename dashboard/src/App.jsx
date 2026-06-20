import { useEffect, useState, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import StatusDot from './components/StatusDot'
import StatCard from './components/StatCard'
import ThreatRow from './components/ThreatRow'
import ThreatDetail from './components/ThreatDetail'
import { getStatus, getStats, getThreats, getThreatDetail } from './api'

export default function App() {
  const [status, setStatus] = useState(null)
  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState(null)

  const [latestId, setLatestId] = useState(null)

const refresh = useCallback(async () => {
    try {
      const [s, st, t] = await Promise.all([
        getStatus(),
        getStats(),
        getThreats({ limit: 30, verdict: filter }),
      ])
      setStatus(s)
      setStats(st)

      // Detect newest email by comparing to previous top
      if (t.length > 0 && threats.length > 0 && t[0].id !== threats[0]?.id) {
        setLatestId(t[0].id)
        setTimeout(() => setLatestId(null), 2000)
      }

      setThreats(t)
    } catch (e) {
      console.error('Refresh failed', e)
    }
  }, [filter, threats])

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 5000)
    return () => clearInterval(interval)
  }, [refresh])

  const openThreat = async (id) => {
    const detail = await getThreatDetail(id)
    setSelected(detail)
  }

  const handleMarkedSafe = (id) => {
    setThreats((prev) => prev.filter((t) => t.id !== id))
  }

  return (
    <div className="min-h-screen bg-[var(--color-bg-base)] flex border border-[var(--color-border)]">
      <Sidebar />

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--color-border)]">
          <div>
            <p className="text-[13px] font-medium tracking-wide">PHISHGUARD</p>
            <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
              Nepal Government Email Security
            </p>
          </div>
          <div className="flex gap-3.5">
            <StatusDot label="ollama" ok={status?.ollama} />
            <StatusDot label="redis" ok={status?.redis} />
            <StatusDot label="db" ok={status?.database} />
          </div>
        </div>

        <div className="grid grid-cols-4 gap-px bg-[var(--color-border)]">
          <StatCard label="Scanned today" value={stats?.total_emails ?? '—'} />
          <StatCard label="Scam blocked" value={stats?.total_scams ?? '—'} color="var(--color-scam-text)" />
          <StatCard label="Suspicious" value={stats?.total_suspicious ?? '—'} color="var(--color-suspicious-text)" />
          <StatCard label="Avg risk score" value={stats?.avg_risk_score ?? '—'} />
        </div>

        <div className="px-5 pt-4 pb-1 flex items-center justify-between">
          <div className="flex gap-3">
            {['ALL', 'SCAM', 'SUSPICIOUS', 'SAFE'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f === 'ALL' ? null : f)}
                className="text-[11px] tracking-wide"
                style={{
                  color: (filter === f || (f === 'ALL' && !filter))
                    ? 'var(--color-text-primary)'
                    : 'var(--color-text-muted)'
                }}
              >
                {f}
              </button>
            ))}
          </div>
          <p className="text-[11px] font-mono text-[var(--color-safe)]">● live</p>
        </div>

        <div className="px-5 pb-5 space-y-4">
          {threats.length === 0 && (
            <p className="text-[13px] text-[var(--color-text-muted)] py-8 text-center">
              No emails analyzed yet. Waiting for next scan cycle.
            </p>
          )}

          {(() => {
            const primary = threats.filter(t => (t.gmail_category || 'primary') === 'primary')
            const other = threats.filter(t => (t.gmail_category || 'primary') !== 'primary')

            return (
              <>
                {primary.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-[11px] text-[var(--color-text-muted)] tracking-wide px-1">
                      PRIMARY INBOX — {primary.length}
                    </p>
                    {primary.map((t) => (
                      <ThreatRow key={t.id} threat={t} onClick={() => openThreat(t.id)} isNew={t.id === latestId} />
                    ))}
                  </div>
                )}

                {other.length > 0 && (
                  <div className="space-y-1.5 opacity-70">
                    <p className="text-[11px] text-[var(--color-text-muted)] tracking-wide px-1">
                      PROMOTIONS &amp; UPDATES — {other.length}
                    </p>
                    {other.map((t) => (
                      <ThreatRow key={t.id} threat={t} onClick={() => openThreat(t.id)} isNew={t.id === latestId} />
                    ))}
                  </div>
                )}
              </>
            )
          })()}
        </div>
      </div>

      {selected && (
        <ThreatDetail
          threat={selected}
          onClose={() => setSelected(null)}
          onMarkedSafe={handleMarkedSafe}
        />
      )}
    </div>
  )
}