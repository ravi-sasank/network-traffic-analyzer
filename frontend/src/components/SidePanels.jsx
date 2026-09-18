import { bytes, num, uptime } from '../lib/format'
import { proto as protoColor } from '../lib/theme'

export function TelemetryPanel({ stats, connected, startedAt }) {
  const rows = [
    ['flows · 1h', num(stats?.flows_last_hour ?? 0)],
    ['packets · 1h', num(stats?.packets_last_hour ?? 0)],
    ['bytes · 1h', bytes(stats?.bytes_last_hour ?? 0)],
    ['active hosts', num(stats?.active_devices ?? 0)],
    ['alerts · 1h', num(stats?.alerts_last_hour ?? 0)],
    ['session', uptime((Date.now() - startedAt) / 1000)],
    ['feed', connected ? 'CONNECTED' : 'DOWN'],
  ]
  return (
    <>
      {rows.map(([k, v], i) => (
        <div key={k} className={`flex justify-between items-baseline py-[5px]
             ${i < rows.length - 1 ? 'border-b border-[#1b2a448c]' : ''}`}>
          <span className="text-[10.5px] text-[#a3b5cc] tracking-[.4px]">{k}</span>
          <span className={`text-[11.5px] font-semibold tracking-[.3px]
            ${k === 'feed' ? (connected ? 'text-[#4ee8a8]' : 'text-[#ff5470]') : 'text-[#e8eff8]'}`}>{v}</span>
        </div>
      ))}
    </>
  )
}

export function ProtocolMix({ protocols = [] }) {
  const total = protocols.reduce((s, p) => s + (p.bytes || 0), 0) || 1
  if (!protocols.length) {
    return <div className="text-[10.5px] text-[#6b7f99] py-2">Awaiting traffic.</div>
  }
  return (
    <>
      {protocols.map(p => {
        const pct = (p.bytes / total) * 100
        const c = protoColor(p.protocol)
        return (
          <div key={p.protocol} className="mb-[10px] last:mb-0">
            <div className="flex justify-between items-center text-[10.5px] mb-[4px]">
              <span className="text-[#e8eff8] font-medium flex items-center gap-[6px]">
                <i className="w-[6px] h-[6px] rounded-full shrink-0"
                   style={{ background: c, boxShadow: `0 0 5px ${c}` }} />
                {p.protocol}
              </span>
              <span className="text-[#a3b5cc]">{bytes(p.bytes)} · {pct.toFixed(1)}%</span>
            </div>
            <div className="h-[3px] bg-[#111d31] relative overflow-hidden">
              <i className="absolute left-0 top-0 h-full transition-all duration-700"
                 style={{ width: `${pct}%`, background: c, boxShadow: `0 0 7px ${c}77` }} />
            </div>
          </div>
        )
      })}
    </>
  )
}

const RULES = [
  ['port_scan', '≥15 ports · p99 obs 3'],
  ['connection_burst', '≥421 conn · p99 obs 210'],
  ['dns_exfil', '≥30 char · entropy ≥3.5'],
  ['icmp_sweep', '≥10 hosts'],
  ['volume_anomaly', 'z ≥ 3.5σ · floor 50 KB'],
]

export function RulesPanel() {
  return (
    <>
      {RULES.map(([name, detail]) => (
        <div key={name} className="mb-[6px] last:mb-0">
          <div className="flex justify-between items-baseline">
            <span className="text-[10.5px] text-[#a3b5cc]">{name}</span>
            <span className="text-[10px] font-semibold text-[#4ee8a8] tracking-[.6px]">ARMED</span>
          </div>
          <div className="text-[9px] text-[#6b7f99] pl-[9px] mt-[2px]">{detail}</div>
        </div>
      ))}
      <div className="mt-[8px] pt-[7px] border-t border-[#1b2a448c] text-[8px] text-[#6b7f99] leading-[1.5]">
        Thresholds derived at the 99th percentile of observed traffic.
      </div>
    </>
  )
}
