import { useMemo } from 'react'
import { bytes } from '../lib/format'

export default function ThroughputChart({ timeline = [] }) {
  const { path, area, avg, peak, last } = useMemo(() => {
    if (!timeline.length) return {}
    const W = 320, H = 100
    const d = timeline.map(t => t.bytes || 0)
    // 5-point moving average gives context for spikes
    const ma = d.map((_, i) => {
      const w = d.slice(Math.max(0, i - 4), i + 1)
      return w.reduce((a, b) => a + b, 0) / w.length
    })
    const mx = Math.max(...d, 1) * 1.1
    const P = arr => arr.map((v, i) =>
      `${(i / Math.max(1, arr.length - 1) * W).toFixed(1)},${(H - v / mx * (H - 10) - 5).toFixed(1)}`
    ).join(' ')
    return {
      path: P(d), avg: P(ma), area: `0,${H} ${P(d)} ${W},${H}`,
      peak: Math.max(...d), last: d[d.length - 1],
    }
  }, [timeline])

  if (!timeline.length) {
    return <div className="flex-1 flex items-center justify-center text-[10px] text-[#6b7f99]">
      Awaiting traffic data.
    </div>
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="flex gap-[12px] text-[8px] text-[#6b7f99] tracking-[1px] px-[10px] pt-[5px] font-medium">
        <span><i className="inline-block w-[14px] h-[2px] mr-[4px] align-middle bg-[#7deef9]" />LIVE</span>
        <span><i className="inline-block w-[14px] h-[2px] mr-[4px] align-middle bg-[#b0a1ff] opacity-80" />5-MIN AVG</span>
        <span className="ml-auto text-[#a3b5cc]">peak {bytes(peak)}</span>
      </div>
      <div className="flex-1 px-[10px] pb-[8px] pt-[2px] min-h-0">
        <svg width="100%" height="100%" viewBox="0 0 320 100" preserveAspectRatio="none">
          <defs>
            <linearGradient id="tpg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#7deef9" stopOpacity=".42" />
              <stop offset="55%" stopColor="#38d9ef" stopOpacity=".14" />
              <stop offset="100%" stopColor="#0e7490" stopOpacity="0" />
            </linearGradient>
          </defs>
          <line x1="0" y1="33" x2="320" y2="33" stroke="#1b2a44" strokeWidth="1" strokeDasharray="2 5" />
          <line x1="0" y1="66" x2="320" y2="66" stroke="#1b2a44" strokeWidth="1" strokeDasharray="2 5" />
          <polygon points={area} fill="url(#tpg)" />
          <polyline points={avg} fill="none" stroke="#b0a1ff" strokeWidth="1.1" strokeDasharray="3 3" opacity=".85" />
          <polyline points={path} fill="none" stroke="#7deef9" strokeWidth="1.4" />
        </svg>
      </div>
    </div>
  )
}
