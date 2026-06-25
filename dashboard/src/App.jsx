import { useEffect, useState, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import StatusDot from './components/StatusDot'
import AttentionCard from './components/AttentionCard'
import ThreatRow from './components/ThreatRow'
import ThreatDetail from './components/ThreatDetail'
import { getStatus, getAttentionState, getThreats, getThreatDetail, markHandled } from './api'

export default function App() {
  const [status, setStatus] = useState(null)
  const [attention, setAttention] = useState(null)
  const [showLog, setShowLog] = useState(false)
  const [logThreats, setLogThreats] = useState([])
  const [selected, setSelected] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([getStatus(), getAttentionState()])
      setStatus(s)
      setAttention(a)
    } catch (e) {
      console.error('Refresh failed', e)
    }
  }, [])

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 5000)
    return () => clearInterval(interval)
  }, [refresh])

  const openThreat = async (id) => {
    const detail = await getThreatDetail(id)
    setSelected(detail)
  }

  const handleHandled = async (id) => {
    await markHandled(id)
    refresh()
  }

  const openFullLog = async () => {
    const t = await getThreats({ limit: 50 })
    setLogThreats(t)
    setShowLog(true)
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

        <AttentionCard state={attention} onViewDetails={openThreat} onHandled={handleHandled} />

        <div className="px-5 pb-5">
          <button
            onClick={openFullLog}
            className="text-[11px] text-[var(--color-text-muted)] underline"
          >
            View full activity log
          </button>
        </div>

        {showLog && (
          <div className="px-5 pb-5 space-y-1.5 border-t border-[var(--color-border)] pt-4">
            <p className="text-[11px] text-[var(--color-text-muted)] mb-2">
              Full activity — includes newsletters and low-risk mail
            </p>
            {logThreats.map((t) => (
              <ThreatRow key={t.id} threat={t} onClick={() => openThreat(t.id)} />
            ))}
          </div>
        )}
      </div>

      {selected && (
        <ThreatDetail
          threat={selected}
          onClose={() => setSelected(null)}
          onMarkedSafe={() => { setSelected(null); refresh(); }}
        />
      )}
    </div>
  )
}