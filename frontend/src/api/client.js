const BASE = '' // same-origin; Vite proxies /api to FastAPI

async function get(path) {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`${path} → ${r.status}`)
  return r.json()
}

export const api = {
  health:      () => get('/api/health'),
  stats:       () => get('/api/stats'),
  alerts:      (limit = 60) => get(`/api/alerts?limit=${limit}`),
  threatBoard: () => get('/api/threat-board'),
  protocols:   () => get('/api/protocols'),
  timeline:    (minutes = 30) => get(`/api/timeline?minutes=${minutes}`),
  topTalkers:  (limit = 25) => get(`/api/top-talkers?limit=${limit}`),
  packets:     (limit = 40) => get(`/api/packets?limit=${limit}`),
  domains:     (limit = 15) => get(`/api/domains?limit=${limit}`),
}

import { useEffect, useRef, useState } from 'react'

/** Poll a REST endpoint on an interval. Keeps the previous value while
 *  refetching so panels never flash empty. */
export function usePoll(fn, ms = 5000, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    let timer
    const tick = async () => {
      try {
        const d = await fn()
        if (alive.current) { setData(d); setError(null) }
      } catch (e) {
        if (alive.current) setError(e)
      } finally {
        if (alive.current) setLoading(false)
      }
      timer = setTimeout(tick, ms)
    }
    tick()
    return () => { alive.current = false; clearTimeout(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { data, error, loading }
}
