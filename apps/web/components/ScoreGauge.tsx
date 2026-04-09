import { Severity } from '@/types/scan'
import { SEVERITY_CONFIG } from '@/lib/severity'

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const normalized = severity?.toUpperCase() as Severity
  const cfg = SEVERITY_CONFIG[normalized] ?? SEVERITY_CONFIG['INFO']
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}