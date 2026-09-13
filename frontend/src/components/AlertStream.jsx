import { sev, ruleIcon, ruleLabel } from '../lib/theme'
import { ago } from '../lib/format'

export default function AlertStream({ alerts = [], selected, onSelect, newestId }) {
  const shown = selected ? alerts.filter(a => a.src_ip === selected) : alerts

  if (!shown.length) {
    return <div className="text-[10.5px] text-[#6b7f99] leading-relaxed py-2">
      {selected ? `No alerts recorded for ${selected}.` : 'No alerts. Detection is armed and the network is quiet.'}
    </div>
  }

  return (
    <>
      {shown.map(a => {
        const color = sev(a.severity)
        const paths = ruleIcon(a.rule_name)
        const isNew = a.id === newestId
        return (
          <button
            key={a.id}
            onClick={() => onSelect?.(a.src_ip)}
            className={`w-full text-left grid gap-[9px] px-[10px] py-[9px] mb-[6px]
                        border border-[#1b2a44] bg-[#0a1120] ${isNew ? 'enter' : ''}`}
            style={{ gridTemplateColumns: '26px 1fr', borderLeftWidth: 2, borderLeftColor: color }}
          >
            <div className="w-[26px] h-[26px] flex items-center justify-center border rounded-[2px]"
                 style={{ borderColor: `${color}66`, background: `${color}17`, color }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                {paths.map((d, i) => (
                  <path key={i} d={d} stroke="currentColor" strokeWidth="1.3"
                        strokeLinecap="round" strokeLinejoin="round" />
                ))}
              </svg>
            </div>
            <div className="min-w-0">
              <div className="flex justify-between items-center mb-[5px]">
                <span className="text-[9.5px] font-bold tracking-[1.5px]" style={{ color }}>
                  {ruleLabel(a.rule_name)}
                </span>
                <span className="text-[8.5px] text-[#6b7f99] font-medium">{ago(a.ts)} AGO</span>
              </div>
              <div className="text-[10.5px] leading-[1.55] text-[#c9d6e6]">{a.reason}</div>
              {a.evidence && typeof a.evidence === 'object' && (
                <div className="mt-[6px] pt-[6px] border-t border-[#1b2a44a6] flex gap-[11px] flex-wrap">
                  {Object.entries(a.evidence).slice(0, 4).map(([k, v]) => (
                    <span key={k} className="text-[8.5px] text-[#6b7f99] tracking-[.6px] font-medium">
                      {k.replace(/_/g, ' ')} <b className="text-[#a3b5cc] font-semibold">{String(v)}</b>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </button>
        )
      })}
    </>
  )
}
