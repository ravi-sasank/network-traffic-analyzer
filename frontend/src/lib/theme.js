/** Tier colours come from the API's `tier` field — never recomputed
 *  client-side, so the map and the threat board can never disagree. */
export const TIER = {
  critical: { hex: '#ff5470', int: 0xff5470, label: 'CRITICAL' },
  high:     { hex: '#ff9d57', int: 0xff9d57, label: 'HOSTILE'  },
  elevated: { hex: '#ffc861', int: 0xffc861, label: 'ELEVATED' },
  guarded:  { hex: '#7deef9', int: 0x7deef9, label: 'GUARDED'  },
  normal:   { hex: '#7deef9', int: 0x7deef9, label: 'NOMINAL'  },
  quiet:    { hex: '#41577a', int: 0x41577a, label: 'QUIET'    },
}
export const tier = (t) => TIER[t] || TIER.normal

export const SEVERITY = {
  critical: '#ff5470',
  high:     '#ff9d57',
  medium:   '#ffc861',
  low:      '#7deef9',
}
export const sev = (s) => SEVERITY[s] || SEVERITY.low

export const PROTO = {
  TCP: '#7deef9', QUIC: '#b0a1ff', UDP: '#4ee8a8',
  DNS: '#ffc861', ICMP: '#ff5470', ICMPv6: '#ff5470', OTHER: '#6b7f99',
}
export const proto = (p) => PROTO[p] || PROTO.OTHER

/** Rule → SVG paths. Semantic icons make the alert stream scannable
 *  without reading every line. */
export const RULE_ICON = {
  port_scan: ['M8 1.5 2 4v4c0 3.2 2.4 6 6 6.5 3.6-.5 6-3.3 6-6.5V4L8 1.5Z', 'M8 6v4', 'M6 8h4'],
  connection_burst: ['M9 1 3 9h4l-1 6 7-8.5H8.5L9 1Z'],
  volume_anomaly: ['M1 12l3.5-4.5L7 10l3-6 2.5 4.5L15 6'],
  connection_anomaly: ['M1 12l3.5-4.5L7 10l3-6 2.5 4.5L15 6'],
  dns_exfil: ['M1.8 8h12.4', 'M8 1.8c1.6 1.8 2.4 3.9 2.4 6.2S9.6 12.4 8 14.2C6.4 12.4 5.6 10.3 5.6 8S6.4 3.6 8 1.8Z', 'M8 1.8a6.2 6.2 0 1 0 0 12.4 6.2 6.2 0 0 0 0-12.4Z'],
  icmp_sweep: ['M8 3.2A4.8 4.8 0 0 1 12.8 8', 'M8 .8A7.2 7.2 0 0 1 15.2 8', 'M8 7a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z'],
}
export const ruleIcon = (r) => RULE_ICON[r] || ['M8 2v8', 'M8 13h.01']

/** Human label for a rule name. */
export const ruleLabel = (r) => String(r || '').replace(/_/g, ' ').toUpperCase()
