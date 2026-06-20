const LAYER_ORDER = [
  'Authentication',
  'Domain Intelligence',
  'Psychological Analysis',
  'Link Scanner',
  'Sender Behaviour',
  'RAG Patterns',
  'AI Analysis',
]

function barColor(score, max) {
  if (max === 0) return 'var(--color-border)'
  const ratio = score / max
  if (ratio >= 0.6) return 'var(--color-scam)'
  if (ratio >= 0.25) return 'var(--color-suspicious)'
  return 'var(--color-border)'
}

export default function LayerBars({ layerScores = {}, size = 'sm' }) {
  const height = size === 'sm' ? 14 : 28
  const width = size === 'sm' ? 5 : 10

  return (
    <div className="flex gap-0.5" title="Layer scores">
      {LAYER_ORDER.map((layer) => {
        const data = layerScores[layer] || { score: 0, max: 0 }
        return (
          <div
            key={layer}
            style={{
              width,
              height,
              background: barColor(data.score, data.max),
            }}
          />
        )
      })}
    </div>
  )
}