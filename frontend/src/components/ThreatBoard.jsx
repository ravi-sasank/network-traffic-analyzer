import { tier } from '../lib/theme'
import { shortHost } from '../lib/format'

export default function ThreatBoard({ board = [], selected, onSelect, onHover }) {
  if (!board.length) {
    return <div className="text-[10.5px] text-[#6b7f99] leading-relaxed py-2">
      No hosts scored yet. The board populates as detections fire.
    </div>
  }

  return (
    <>
      {board.map(h => {
        const tk = tier(h.tier)
        const hostile = h.tier === 'critical' || h.tier === 'high'
        const isSel = selected === h.host
        const dim = selected && !isSel
        return (
          <button
            key={h.host}
            onClick={() => onSelect?.(isSel ? null : h.host)}
            onMouseEnter={() => onHover?.(h.host)}
            onMouseLeave={() => onHover?.(null)}
            className="w-full text-left grid items-center gap-[10px] px-[10px] py-[9px] mb-[6px]
                       border border-[#1b2a44] bg-[#0a1120] transition-all duration-200"
            style={{
              gridTemplateColumns: '28px 1fr auto',
              borderLeftWidth: 2, borderLeftColor: tk.hex,
              opacity: dim ? 0.4 : 1,
              background: isSel
                ? `linear-gradient(90deg, ${tk.hex}22, #0a1120 60%)`
                : hostile ? `linear-gradient(90deg, ${tk.hex}14, #0a1120 58%)` : '#0a1120',
              boxShadow: isSel ? `inset 0 0 0 1px ${tk.hex}55` : 'none',
            }}
          >
            <svg width="28" height="28" viewBox="0 0 28 28">
              <circle cx="14" cy="14" r={5 + h.score / 22} fill={tk.hex} />
              {h.tier === 'critical' && (
                <circle cx="14" cy="14" r="8" fill="none" stroke={tk.hex} strokeWidth=".8">
                  <animate attributeName="r" values="7;12;7" dur="1.9s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values=".7;0;.7" dur="1.9s" repeatCount="indefinite" />
                </circle>
              )}
              <ellipse cx="14" cy="14" rx="12" ry="4.5" fill="none" stroke={tk.hex}
                       strokeWidth=".6" opacity=".35" transform="rotate(-25 14 14)" />
            </svg>
            <div className="min-w-0">
              <div className="text-[11.5px] font-semibold text-[#e8eff8] truncate" title={h.host}>{shortHost(h.host)}</div>
              <div className="text-[8.5px] tracking-[1.1px] mt-[3px] font-semibold"
                   style={{ color: hostile ? tk.hex : '#6b7f99' }}>
                {tk.label} · {h.alert_count} EVT
              </div>
            </div>
            <div>
              <div className="text-[20px] font-bold leading-none text-right"
                   style={{ color: tk.hex }}>{Math.round(h.score)}</div>
              <div className="h-[2px] bg-[#111d31] mt-[5px] w-[56px] ml-auto relative">
                <i className="absolute left-0 top-0 h-full transition-all duration-500"
                   style={{ width: `${h.score}%`, background: tk.hex }} />
              </div>
            </div>
          </button>
        )
      })}
    </>
  )
}
