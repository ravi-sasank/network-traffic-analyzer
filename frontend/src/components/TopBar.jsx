import { useEffect, useState } from 'react'
import { num, bytes, clock } from '../lib/format'
import { setSoundEnabled, playBlip, onAlarmChange, acknowledge, isSoundEnabled } from '../lib/sound'

function Stat({ label, value, tone = '' }) {
  return (
    <div className="px-3 py-2 border-r border-[#1b2a44] flex flex-col justify-center min-w-0 flex-1 max-w-[130px]">
      <div className="text-[7.5px] text-[#6b7f99] tracking-[1.3px] mb-1 font-medium truncate">{label}</div>
      <div className={`text-[15px] font-semibold leading-none tracking-[.3px] truncate ${tone || 'text-[#e8eff8]'}`}>{value}</div>
    </div>
  )
}

export default function TopBar({ stats, connected, board = [] }) {
  const [t, setT] = useState(clock())
  const [sound, setSound] = useState(() => isSoundEnabled())
  const [alarm, setAlarm] = useState({ active: false, severity: null })

  useEffect(() => { const i = setInterval(() => setT(clock()), 1000); return () => clearInterval(i) }, [])
  useEffect(() => onAlarmChange(setAlarm), [])

  // spacebar acknowledges — a convenience; the button is the real affordance
  useEffect(() => {
    if (!alarm.active) return
    const onKey = e => { if (e.code === 'Space') { e.preventDefault(); acknowledge() } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [alarm.active])

  const toggleSound = () => {
    const next = !sound
    setSound(next)
    setSoundEnabled(next)
    if (next) playBlip()
  }

  const hostile = board.filter(b => b.tier === 'critical' || b.tier === 'high').length
  const top = board[0]?.score || 0
  const level = top >= 80 ? ['CRITICAL', 'text-[#ff5470]']
              : top >= 55 ? ['HIGH', 'text-[#ff9d57]']
              : top >= 30 ? ['ELEVATED', 'text-[#ffc861]']
              : ['NOMINAL', 'text-[#4ee8a8]']

  return (
    <div className="flex h-[54px] flex-shrink-0 border-b border-[#1b2a44] overflow-hidden"
         style={{ background: 'linear-gradient(180deg,rgba(14,23,40,.95),rgba(7,13,24,.88))' }}>
      <div className="flex items-center gap-[10px] px-4 border-r border-[#1b2a44] flex-shrink-0">
        <svg width="24" height="24" viewBox="0 0 26 26" className="flex-shrink-0">
          <circle cx="13" cy="13" r="4" fill="#7deef9" />
          <ellipse cx="13" cy="13" rx="11.5" ry="5" fill="none" stroke="#38d9ef" strokeWidth=".9" opacity=".6" transform="rotate(-28 13 13)" />
          <ellipse cx="13" cy="13" rx="11.5" ry="5" fill="none" stroke="#38d9ef" strokeWidth=".9" opacity=".35" transform="rotate(32 13 13)" />
          <circle cx="23" cy="9" r="1.4" fill="#ff5470" />
        </svg>
        <div>
          <div className="text-[21px] font-bold tracking-[3.5px] leading-none text-white"
               style={{ fontFamily: "'Barlow Condensed',system-ui,sans-serif" }}>SENTINEL</div>
          <div className="text-[7px] text-[#6b7f99] tracking-[1.8px] mt-[3px] font-medium whitespace-nowrap">
            NETWORK SITUATIONAL AWARENESS
          </div>
        </div>
      </div>

      <div className="flex flex-1 min-w-0">
        <Stat label="HOSTS" value={num(stats?.active_devices ?? 0)} tone="text-[#7deef9]" />
        <Stat label="VOLUME 1H" value={bytes(stats?.bytes_last_hour ?? 0)} />
        <Stat label="PACKETS 1H" value={num(stats?.packets_last_hour ?? 0)} />
        <Stat label="FLOWS 1H" value={num(stats?.flows_last_hour ?? 0)} />
        <Stat label="ALERTS 1H" value={num(stats?.alerts_last_hour ?? 0)}
              tone={stats?.alerts_last_hour ? 'text-[#ff5470]' : 'text-[#4ee8a8]'} />
        <Stat label="HOSTILE" value={hostile} tone={hostile ? 'text-[#ff5470]' : 'text-[#4ee8a8]'} />
        <Stat label="THREAT" value={level[0]} tone={level[1]} />
      </div>

      {alarm.active && (
        <button onClick={acknowledge} title="Acknowledge alarm (or press Space)"
                className="flex items-center gap-[7px] px-5 flex-shrink-0 font-bold tracking-[1.8px] text-[11px] text-white"
                style={{
                  background: alarm.severity === 'critical' ? '#c81e3c' : '#c2621d',
                  animation: 'alarmPulse 1.05s ease-in-out infinite',
                }}>
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
            <path d="M8 1.6 1 14h14L8 1.6Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
            <path d="M8 6v3.6M8 11.6h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          ACK
        </button>
      )}

      <div className="flex items-center gap-3 px-4 border-l border-[#1b2a44] flex-shrink-0">
        <div className="flex items-center gap-[6px] text-[9.5px] tracking-[1.2px] font-medium">
          <span className="w-[6px] h-[6px] rounded-full flex-shrink-0"
                style={{ background: connected ? '#4ee8a8' : '#ff5470',
                         boxShadow: `0 0 8px ${connected ? '#4ee8a8' : '#ff5470'}`,
                         animation: 'blip 1.8s infinite' }} />
          <span className={connected ? 'text-[#4ee8a8]' : 'text-[#ff5470]'}>
            {connected ? 'LIVE' : 'RETRY'}
          </span>
        </div>
        <button onClick={toggleSound} title={sound ? 'Mute alarms' : 'Enable alarm audio'}
                className="flex items-center gap-[5px] text-[9.5px] tracking-[1.2px] font-medium
                           border px-[7px] py-[3px] rounded-[2px] transition-colors"
                style={{ color: sound ? '#7deef9' : '#6b7f99',
                         borderColor: sound ? '#2a5d72' : '#1b2a44',
                         background: sound ? 'rgba(125,238,249,.07)' : 'transparent' }}>
          <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
            <path d="M7 3 4 6H2v4h2l3 3V3Z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
            {sound
              ? <path d="M10 5.5a3.5 3.5 0 0 1 0 5M12.2 3.4a6.5 6.5 0 0 1 0 9.2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
              : <path d="M10.5 6.5l3 3m0-3l-3 3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />}
          </svg>
          SFX
        </button>
        <div className="text-[12px] text-[#7deef9] tracking-[1.2px] font-medium">{t}</div>
      </div>

      <style>{`
        @keyframes blip{0%,100%{opacity:1}50%{opacity:.25}}
        @keyframes alarmPulse{0%,100%{filter:brightness(1)}50%{filter:brightness(1.5)}}
      `}</style>
    </div>
  )
}
