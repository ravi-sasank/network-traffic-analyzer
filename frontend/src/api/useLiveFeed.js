import { useEffect, useRef, useState, useCallback } from 'react'

/**
 * Live feed from the backend WebSocket. Pushes new alerts, a refreshed
 * threat board and top-line stats every couple of seconds.
 *
 * Reconnects with backoff so a backend restart doesn't leave a dead UI.
 */
export function useLiveFeed() {
  const [connected, setConnected] = useState(false)
  const [alerts, setAlerts] = useState([])
  const [board, setBoard] = useState([])
  const [stats, setStats] = useState(null)
  const [lastAlertId, setLastAlertId] = useState(null)

  const wsRef = useRef(null)
  const retry = useRef(0)
  const closing = useRef(false)

  const connect = useCallback(() => {
    if (closing.current) return
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws/live`)
    wsRef.current = ws

    ws.onopen = () => { setConnected(true); retry.current = 0 }

    ws.onmessage = (ev) => {
      let msg
      try { msg = JSON.parse(ev.data) } catch { return }

      if (msg.stats) setStats(msg.stats)
      if (Array.isArray(msg.threat_board)) setBoard(msg.threat_board)

      if (Array.isArray(msg.new_alerts) && msg.new_alerts.length) {
        setAlerts(prev => {
          const merged = [...msg.new_alerts.slice().reverse(), ...prev]
          return merged.slice(0, 80)
        })
        setLastAlertId(msg.new_alerts[msg.new_alerts.length - 1].id)
      }
    }

    ws.onclose = () => {
      setConnected(false)
      if (closing.current) return
      const wait = Math.min(8000, 600 * 2 ** retry.current)
      retry.current += 1
      setTimeout(connect, wait)
    }

    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    closing.current = false
    connect()
    return () => {
      closing.current = true
      wsRef.current?.close()
    }
  }, [connect])

  /** Seed the stream with history so the panel isn't empty on first load. */
  const seedAlerts = useCallback((rows) => {
    setAlerts(prev => (prev.length ? prev : rows))
  }, [])

  return { connected, alerts, board, stats, lastAlertId, seedAlerts }
}
