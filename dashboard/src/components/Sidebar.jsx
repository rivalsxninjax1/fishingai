import { ShieldCheck, LayoutDashboard, Mail, AlertTriangle, ListChecks, Settings } from 'lucide-react'

const ICONS = [
  { icon: ShieldCheck, active: true, color: 'var(--color-safe)' },
  { icon: LayoutDashboard, active: false },
  { icon: Mail, active: false },
  { icon: AlertTriangle, active: false },
  { icon: ListChecks, active: false },
]

export default function Sidebar() {
  return (
    <div className="w-14 bg-[var(--color-bg-rail)] border-r border-[var(--color-border)] flex flex-col items-center py-4 gap-6">
      {ICONS.map(({ icon: Icon, color }, i) => (
        <Icon
          key={i}
          size={i === 0 ? 22 : 18}
          color={color || 'var(--color-text-muted)'}
        />
      ))}
      <Settings size={18} color="var(--color-text-muted)" className="mt-auto" />
    </div>
  )
}