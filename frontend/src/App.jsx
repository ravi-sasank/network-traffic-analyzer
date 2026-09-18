import { useState, useRef, useMemo, useEffect } from 'react'
import { api, usePoll } from './api/client'
import { useLiveFeed } from './api/useLiveFeed'
import TopBar from './components/TopBar'
import Panel from './components/Panel'
import OrbitalMap from './components/OrbitalMap'
import ThreatBoard from './components/ThreatBoard'
import AlertStream from './components/AlertStream'
import ContactsTable from './components/ContactsTable'
import ThroughputChart from './components/ThroughputChart'
import { TelemetryPanel, ProtocolMix, RulesPanel } from './components/SidePanels'
import ReportExport from './components/ReportExport'
import { raiseAlarm } from './lib/sound'

export default function App() {
  const startedAt = useRef(Date.now()).current

  // live push feed
  const { connected, alerts: liveAlerts, board: liveBoard, stats: liveStats, lastAlertId, seedAlerts } = useLiveFeed()

  // REST polls for the slower-moving panels
  const { data: seedAlertRows } = usePoll(() => api.alerts(60), 20000)
  const { data: pollBoard } = usePoll(api.threatBoard, 6000)
  const { data: pollStats } = usePoll(api.stats, 6000)
  const { data: protocols } = usePoll(api.protocols, 8000)
  const { data: timeline } = usePoll(() => api.timeline(30), 10000)
  const { data: talkers } = usePoll(() => api.topTalkers(25), 7000)

  // seed the alert stream once so it isn't empty before the first push
  useEffect(() => { if (seedAlertRows?.length) seedAlerts(seedAlertRows) }, [seedAlertRows, seedAlerts])

  // Audible alarm on a genuinely new alert. The WebSocket only pushes alerts
  // newer than the id present at connect time, so every lastAlertId change is
  // already a real live detection — no first-event guard needed.
  const lastHeard = useRef(null)
  useEffect(() => {
    if (!lastAlertId || lastAlertId === lastHeard.current) return
    lastHeard.current = lastAlertId
    const a = liveAlerts.find(x => x.id === lastAlertId)
    if (a) raiseAlarm(a.severity)
  }, [lastAlertId, liveAlerts])

  // prefer live values, fall back to polls
  const stats = liveStats || pollStats
  const board = liveBoard?.length ? liveBoard : (pollBoard || [])
  const alerts = liveAlerts.length ? liveAlerts : (seedAlertRows || [])

  // cross-panel selection: one host highlighted everywhere at once
  const [selected, setSelected] = useState(null)
  const [hovered, setHovered] = useState(null)
  const focus = selected || hovered

  const talkerRows = useMemo(() => talkers || [], [talkers])

  return (
    <div className="relative z-[2] h-screen flex flex-col">
      <TopBar stats={stats} connected={connected} board={board} />

      <div className="flex-1 grid min-h-0" style={{ gridTemplateColumns: '238px 1fr 306px' }}>
        {/* LEFT RAIL */}
        <div className="flex flex-col min-h-0 border-r border-[#1b2a44] bg-[#070d1899]">
          <Panel title="TELEMETRY" meta="LIVE" className="flex-none">
            <TelemetryPanel stats={stats} connected={connected} startedAt={startedAt} />
          </Panel>
          <Panel title="PROTOCOL MIX" meta="1H" className="flex-none">
            <ProtocolMix protocols={protocols || []} />
          </Panel>
          <Panel title="RULES" meta="CALIBRATED" className="flex-1 min-h-0">
            <RulesPanel />
          </Panel>
          <Panel title="EXPORT" meta="LIVE DATA" className="flex-none border-b-0">
            <ReportExport />
          </Panel>
        </div>

        {/* CENTER */}
        <div className="flex flex-col min-h-0">
          <div className="flex-1 flex flex-col min-h-0">
            <div className="panel-head">
              <h2 className="panel-title">ORBITAL NETWORK MAP</h2>
              <span className="panel-meta">
                {focus ? `TRACKING ${focus}` : 'ORBIT = TRUST BOUNDARY · RADIUS = THROUGHPUT (LOG)'}
              </span>
            </div>
            <div className="flex-1 relative min-h-0">
              <OrbitalMap
                board={board}
                talkers={talkerRows}
                protocols={protocols || []}
                selected={selected}
                onSelect={setSelected}
                onHover={setHovered}
              />
              {/* HUD overlay */}
              <div className="absolute inset-0 pointer-events-none p-[11px_15px] flex flex-col justify-between">
                <div className="flex justify-between items-start">
                  <div className="text-[8.5px] text-[#6b7f99] tracking-[1.4px] leading-[1.8] font-medium">
                    CONTACTS <b className="text-[#7deef9] font-semibold">{talkerRows.length}</b><br />
                    SCORED <b className="text-[#7deef9] font-semibold">{board.length}</b><br />
                    MODE <b className="text-[#7deef9] font-semibold">LIVE TRACK</b>
                  </div>
                  <div className="text-[8.5px] text-[#6b7f99] tracking-[1.4px] leading-[1.8] font-medium text-right">
                    HOSTILE <b className="text-[#ff5470] font-semibold">
                      {board.filter(b => b.tier === 'critical' || b.tier === 'high').length}</b><br />
                    ALERTS <b className="text-[#7deef9] font-semibold">{alerts.length}</b>
                  </div>
                </div>
                <div className="flex justify-between items-end">
                  <div className="text-[8.5px] text-[#6b7f99] tracking-[1.4px] leading-[1.8] font-medium">
                    ORBIT 1–2 · LAN<br />ORBIT 3 · EDGE / CDN<br />ORBIT 4–5 · EXTERNAL
                  </div>
                  <div className="text-[8.5px] text-[#6b7f99] tracking-[1.4px] font-medium">
                    DRAG TO ROTATE · SCROLL TO ZOOM · CLICK TO TRACK
                  </div>
                </div>
              </div>
              {[['top-[6px] left-[6px] border-t border-l'], ['top-[6px] right-[6px] border-t border-r'],
                ['bottom-[6px] left-[6px] border-b border-l'], ['bottom-[6px] right-[6px] border-b border-r']]
                .map(([c], i) => (
                  <div key={i} className={`absolute w-[14px] h-[14px] border-[#2a3d5c] pointer-events-none ${c}`} />
              ))}
            </div>
          </div>

          {/* bottom strip */}
          <div className="h-[164px] border-t border-[#1b2a44] grid flex-shrink-0 bg-[#070d18a6]"
               style={{ gridTemplateColumns: '1fr 322px' }}>
            <div className="border-r border-[#1b2a44] flex flex-col min-h-0">
              <div className="panel-head">
                <h2 className="panel-title">ACTIVE CONTACTS</h2>
                <span className="panel-meta">TOP HOSTS BY VOLUME · 1H</span>
              </div>
              <div className="overflow-y-auto flex-1 min-h-0">
                <ContactsTable talkers={talkerRows} selected={selected}
                               onSelect={setSelected} onHover={setHovered} />
              </div>
            </div>
            <div className="flex flex-col min-h-0">
              <div className="panel-head">
                <h2 className="panel-title">THROUGHPUT</h2>
                <span className="panel-meta">30 MIN</span>
              </div>
              <ThroughputChart timeline={timeline || []} />
            </div>
          </div>
        </div>

        {/* RIGHT RAIL */}
        <div className="flex flex-col min-h-0 border-l border-[#1b2a44] bg-[#070d1899]">
          <Panel title="THREAT BOARD" meta="DECAY λ 10M" className="flex-none max-h-[46%]">
            <ThreatBoard board={board} selected={selected}
                         onSelect={setSelected} onHover={setHovered} />
          </Panel>
          <Panel title="ALERT STREAM"
                 meta={selected ? `FILTERED · ${selected}` : 'LIVE'}
                 className="flex-1 border-b-0">
            <AlertStream alerts={alerts} selected={selected}
                         onSelect={setSelected} newestId={lastAlertId} />
          </Panel>
        </div>
      </div>
    </div>
  )
}
