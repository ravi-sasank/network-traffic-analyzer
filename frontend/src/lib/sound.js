/**
 * SOC alarm engine.
 *
 * The alarm is a real emergency-siren recording (public-domain, Freesound),
 * trimmed to one seamless 4-second cycle: three 0.55s blasts with reverb
 * tails, then a 1s gap. Synthesis was tried first but a real recording with
 * genuine room reverb is unmistakably more convincing.
 *
 * Alarms LOOP until acknowledged — a one-shot chirp is useless if the
 * analyst has stepped away from the console.
 */

const ALARM_SRC = '/audio/alarm-loop.mp3'

let enabled = (() => {
  try { return localStorage.getItem('sentinel.sfx') === '1' } catch { return false }
})()

let audio = null
let currentSeverity = null
const listeners = new Set()

/* per-severity behaviour: how loud, and whether it loops until ACK */
const PROFILE = {
  critical: { volume: 0.85, loop: true },
  high:     { volume: 0.62, loop: true },
  medium:   { volume: 0.40, loop: false },
  low:      { volume: 0.26, loop: false },
}

function el() {
  if (!audio) {
    audio = new Audio(ALARM_SRC)
    audio.preload = 'auto'
    audio.addEventListener('ended', () => {
      // non-looping severities clear themselves when the clip finishes
      if (!audio.loop) { currentSeverity = null; notify() }
    })
  }
  return audio
}

export function setSoundEnabled(on) {
  enabled = on
  try { localStorage.setItem('sentinel.sfx', on ? '1' : '0') } catch { /* ignore */ }
  if (on) el().load()          // warm the buffer on the user gesture
  else stopAlarm()
}
export function isSoundEnabled() { return enabled }

export function onAlarmChange(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
function notify() {
  const state = { active: !!currentSeverity, severity: currentSeverity }
  listeners.forEach(fn => fn(state))
}

export function raiseAlarm(severity = 'medium') {
  if (!enabled) return
  const rank = { low: 0, medium: 1, high: 2, critical: 3 }
  // never downgrade an alarm that's already sounding
  if (currentSeverity && rank[severity] <= rank[currentSeverity]) return

  const p = PROFILE[severity] || PROFILE.medium
  const a = el()
  a.loop = p.loop
  a.volume = p.volume
  a.currentTime = 0
  a.play().catch(() => { /* blocked until a user gesture — SFX toggle covers this */ })

  currentSeverity = severity
  notify()
}

/** Acknowledge — silences the alarm. The analyst's action. */
export function acknowledge() { stopAlarm() }

function stopAlarm() {
  if (audio) {
    audio.pause()
    audio.currentTime = 0
    audio.loop = false
  }
  currentSeverity = null
  notify()
}

export function alarmState() {
  return { active: !!currentSeverity, severity: currentSeverity }
}

/** Soft UI confirmation blip — synthesised, deliberately pleasant. */
export function playBlip() {
  if (!enabled) return
  try {
    const AC = window.AudioContext || window.webkitAudioContext
    const c = new AC()
    const at = c.currentTime
    const g = c.createGain()
    g.gain.setValueAtTime(0.0001, at)
    g.gain.exponentialRampToValueAtTime(0.05, at + 0.01)
    g.gain.exponentialRampToValueAtTime(0.0001, at + 0.11)
    g.connect(c.destination)
    const o = c.createOscillator()
    o.type = 'sine'
    o.frequency.setValueAtTime(880, at)
    o.frequency.exponentialRampToValueAtTime(1320, at + 0.09)
    o.connect(g); o.start(at); o.stop(at + 0.14)
    setTimeout(() => c.close(), 400)
  } catch { /* ignore */ }
}

/* Safety net: Escape always silences, even if the ACK button failed to
   render. An alarm you cannot stop is worse than no alarm at all. */
if (typeof window !== 'undefined') {
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') acknowledge()
  })
  window.__sentinelStopAlarm = acknowledge
}
