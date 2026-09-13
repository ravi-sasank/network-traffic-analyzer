export function bytes(n) {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = Number(n)
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v < 10 && i > 0 ? v.toFixed(2) : v.toFixed(i ? 1 : 0)} ${u[i]}`
}

export function num(n) {
  if (n == null) return '—'
  return Number(n).toLocaleString('en-US')
}

export function ago(ts) {
  if (!ts) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

export function clock() {
  return new Date().toISOString().slice(11, 19) + 'Z'
}

export function uptime(sec) {
  const h = String(Math.floor(sec / 3600)).padStart(2, '0')
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0')
  const s = String(Math.floor(sec % 60)).padStart(2, '0')
  return `${h}:${m}:${s}`
}

/** Log scale — traffic spans orders of magnitude, so linear sizing is wrong. */
export function logScale(v, min, max, outMin, outMax) {
  const lv = Math.log10(Math.max(1, v))
  const lo = Math.log10(Math.max(1, min))
  const hi = Math.log10(Math.max(2, max))
  const t = Math.max(0, Math.min(1, (lv - lo) / (hi - lo || 1)))
  return outMin + t * (outMax - outMin)
}

/** Is this address on our own network? Mirrors the backend's classification. */
export function isPrivate(ip) {
  if (!ip) return false
  const s = String(ip).toLowerCase()
  return /^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(s)
      || s.startsWith('fe80:') || s.startsWith('fc') || s.startsWith('fd') || s === '::1'
}

/** IPv6 addresses are enormous and blow out table columns. Shorten to
 *  first + last group so the host is still identifiable. */
export function shortHost(ip) {
  if (!ip) return '—'
  const s = String(ip)
  if (!s.includes(':')) return s          // IPv4 as-is
  const parts = s.split(':').filter(Boolean)
  if (parts.length <= 3) return s
  return `${parts[0]}:${parts[1]}…${parts[parts.length - 1]}`
}
