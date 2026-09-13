import { bytes, num, shortHost } from '../lib/format'
import { proto as protoColor } from '../lib/theme'

export default function ContactsTable({ talkers = [], selected, onSelect, onHover }) {
  if (!talkers.length) {
    return <div className="p-3 text-[10.5px] text-[#6b7f99]">
      No flows captured yet. Start the capture service to populate this table.
    </div>
  }
  return (
    <table className="w-full border-collapse text-[10.5px]">
      <thead>
        <tr>
          {['HOST', 'FLOWS', 'PEERS', 'VOLUME', 'SHARE'].map((h, i) => (
            <th key={h} className={`sticky top-0 bg-[#0e1728] border-b border-[#1b2a44]
                 px-[9px] py-[6px] font-semibold text-[8px] tracking-[1.4px] text-[#6b7f99]
                 ${i > 1 ? 'text-right' : 'text-left'}`}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {talkers.map(t => {
          const max = Math.max(...talkers.map(x => x.bytes || 1))
          const pct = ((t.bytes || 0) / max) * 100
          const isSel = selected === t.src_ip
          return (
            <tr key={t.src_ip}
                onClick={() => onSelect?.(isSel ? null : t.src_ip)}
                onMouseEnter={() => onHover?.(t.src_ip)}
                onMouseLeave={() => onHover?.(null)}
                className="cursor-pointer transition-colors"
                style={{
                  background: isSel ? 'rgba(125,238,249,.09)' : 'transparent',
                  opacity: selected && !isSel ? 0.45 : 1,
                }}>
              <td className="px-[9px] py-[6px] border-b border-[#1b2a4473] text-[#e8eff8] font-medium"
                  title={t.src_ip}>
                {shortHost(t.src_ip)}
              </td>
              <td className="px-[9px] py-[6px] border-b border-[#1b2a4473] text-[#a3b5cc]">
                {num(t.flows)}
              </td>
              <td className="px-[9px] py-[6px] border-b border-[#1b2a4473] text-[#a3b5cc] text-right">
                {num(t.peers)}
              </td>
              <td className="px-[9px] py-[6px] border-b border-[#1b2a4473] text-[#e8eff8] font-semibold text-right">
                {bytes(t.bytes)}
              </td>
              <td className="px-[9px] py-[6px] border-b border-[#1b2a4473] w-[86px]">
                <div className="h-[3px] bg-[#111d31] relative">
                  <i className="absolute left-0 top-0 h-full bg-[#38d9ef]" style={{ width: `${pct}%` }} />
                </div>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
