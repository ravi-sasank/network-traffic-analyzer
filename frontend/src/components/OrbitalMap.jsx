import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { tier, proto as protoColor } from '../lib/theme'
import { logScale, isPrivate, shortHost } from '../lib/format'

const RINGS = [34, 56, 78, 100, 122, 144, 166]
const MAX_NODES = 140
const PPL = 4   // particles per traffic link

function makeGlowTexture() {
  const c = document.createElement('canvas')
  c.width = c.height = 128
  const x = c.getContext('2d')
  const g = x.createRadialGradient(64, 64, 0, 64, 64, 64)
  g.addColorStop(0, 'rgba(255,255,255,1)')
  g.addColorStop(0.16, 'rgba(255,255,255,0.55)')
  g.addColorStop(0.42, 'rgba(255,255,255,0.14)')
  g.addColorStop(1, 'rgba(255,255,255,0)')
  x.fillStyle = g; x.fillRect(0, 0, 128, 128)
  return new THREE.CanvasTexture(c)
}

/** Orbit placement: LAN hosts sit close to the core, external hosts further
 *  out, sub-divided by traffic volume so the system has real depth. */
function ringFor(host, talkers, maxBytes) {
  const t = talkers?.find(x => x.src_ip === host)
  const b = t?.bytes || 0
  const share = maxBytes ? b / maxBytes : 0
  if (isPrivate(host)) {
    if (share > 0.30) return 1
    if (share > 0.08) return 2
    return 3
  }
  if (share > 0.35) return 4
  if (share > 0.12) return 5
  return share > 0.03 ? 6 : 7
}

export default function OrbitalMap({ board = [], talkers = [], protocols = [], selected, onSelect, onHover }) {
  const mountRef = useRef(null)
  const labelsRef = useRef(null)
  const stateRef = useRef({})
  const dataRef = useRef({ board, talkers, selected })
  useEffect(() => { dataRef.current = { board, talkers, selected } }, [board, talkers, selected])

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2))
    mount.appendChild(renderer.domElement)
    renderer.domElement.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;cursor:grab;display:block'

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(46, 1, 0.1, 3000)
    const sphere = new THREE.SphereGeometry(1, 18, 18)
    const glowTex = makeGlowTexture()
    const matCache = new Map()
    const matFor = h => { if (!matCache.has(h)) matCache.set(h, new THREE.MeshBasicMaterial({ color: h })); return matCache.get(h) }
    const makeGlow = (h, o) => new THREE.Sprite(new THREE.SpriteMaterial({
      map: glowTex, color: h, transparent: true, opacity: o,
      blending: THREE.AdditiveBlending, depthWrite: false }))

    const core = new THREE.Mesh(sphere, new THREE.MeshBasicMaterial({ color: 0xffffff }))
    core.scale.setScalar(6.5); scene.add(core)
    const cg1 = makeGlow(0xffffff, .95); cg1.scale.set(34, 34, 1); scene.add(cg1)
    const cg2 = makeGlow(0x7deef9, .7);  cg2.scale.set(78, 78, 1); scene.add(cg2)
    const cg3 = makeGlow(0x2a9fd4, .3);  cg3.scale.set(172, 172, 1); scene.add(cg3)

    const cp = []
    for (let a = 0; a <= 96; a++) { const t = a / 96 * Math.PI * 2; cp.push(new THREE.Vector3(Math.cos(t) * 11, 0, Math.sin(t) * 11)) }
    const corona = new THREE.Line(new THREE.BufferGeometry().setFromPoints(cp),
      new THREE.LineBasicMaterial({ color: 0x7deef9, transparent: true, opacity: .32 }))
    corona.rotation.x = Math.PI / 2.8; scene.add(corona)

    /* deep starfield inside the scene — gives real parallax when rotating */
    {
      const N = 1400
      const pos = new Float32Array(N * 3)
      const col = new Float32Array(N * 3)
      for (let i = 0; i < N; i++) {
        // shell distribution well beyond the outermost orbit
        const r = 480 + Math.random() * 1600
        const th = Math.random() * Math.PI * 2
        const ph = Math.acos(2 * Math.random() - 1)
        pos[i*3]   = r * Math.sin(ph) * Math.cos(th)
        pos[i*3+1] = r * Math.cos(ph) * 0.55
        pos[i*3+2] = r * Math.sin(ph) * Math.sin(th)
        // subtle colour variation — most white, some blue/amber
        const tint = Math.random()
        col[i*3]   = tint > .88 ? 1.0 : tint > .74 ? 0.72 : 0.86
        col[i*3+1] = tint > .88 ? 0.88 : tint > .74 ? 0.82 : 0.9
        col[i*3+2] = tint > .88 ? 0.66 : 1.0
      }
      const g = new THREE.BufferGeometry()
      g.setAttribute('position', new THREE.BufferAttribute(pos, 3))
      g.setAttribute('color', new THREE.BufferAttribute(col, 3))
      scene.add(new THREE.Points(g, new THREE.PointsMaterial({
        size: 1.5, vertexColors: true, transparent: true, opacity: .75,
        blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true,
      })))
    }

    /* asteroid belt between the middle orbits — texture and density */
    {
      const N = 520
      const pos = new Float32Array(N * 3)
      for (let i = 0; i < N; i++) {
        const r = 110 + Math.random() * 11
        const th = Math.random() * Math.PI * 2
        pos[i*3]   = Math.cos(th) * r
        pos[i*3+1] = (Math.random() - .5) * 5
        pos[i*3+2] = Math.sin(th) * r
      }
      const g = new THREE.BufferGeometry()
      g.setAttribute('position', new THREE.BufferAttribute(pos, 3))
      const belt = new THREE.Points(g, new THREE.PointsMaterial({
        color: 0x4a6a8a, size: 1.1, transparent: true, opacity: .5,
        depthWrite: false, sizeAttenuation: true,
      }))
      scene.add(belt)
      stateRef.current.belt = belt
    }

    RINGS.forEach((r, i) => {
      const pts = []
      for (let a = 0; a <= 180; a++) { const t = a / 180 * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(t) * r, 0, Math.sin(t) * r)) }
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
        new THREE.LineBasicMaterial({ color: [0x2d5b78, 0x28536e, 0x234a64, 0x1e415a, 0x193850, 0x152f44, 0x11263a][i] || 0x11263a, transparent: true, opacity: .68 - i * 0.065 })))
    })
    const polar = new THREE.PolarGridHelper(150, 8, 3, 64, 0x101c2b, 0x101c2b)
    polar.material.transparent = true; polar.material.opacity = .28; scene.add(polar)

    const cam = { az: Math.PI * .25, el: .55, dist: 480, tAz: Math.PI * .25, tEl: .58, tDist: 480 }
    const applyCam = () => {
      const d = cam.dist
      camera.position.set(Math.cos(cam.el) * Math.cos(cam.az) * d, Math.sin(cam.el) * d, Math.cos(cam.el) * Math.sin(cam.az) * d)
      camera.lookAt(0, 0, 0)
    }

    let dragging = false, px = 0, py = 0, hovered = null
    const el = renderer.domElement
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2(-10, -10)
    const onDown = e => { dragging = true; px = e.clientX; py = e.clientY; el.style.cursor = 'grabbing' }
    const onUp = () => { dragging = false; el.style.cursor = hovered ? 'pointer' : 'grab' }
    const onMove = e => {
      const r = el.getBoundingClientRect()
      pointer.x = ((e.clientX - r.left) / r.width) * 2 - 1
      pointer.y = -((e.clientY - r.top) / r.height) * 2 + 1
      if (!dragging) return
      cam.tAz -= (e.clientX - px) * .0062
      cam.tEl = Math.max(0.16, Math.min(1.12, cam.tEl + (e.clientY - py) * .005))
      px = e.clientX; py = e.clientY
    }
    const onWheel = e => { e.preventDefault(); cam.tDist = Math.max(70, Math.min(1400, cam.tDist * (1 + Math.sign(e.deltaY) * .11))) }
    const onClick = () => { const d = dataRef.current; onSelect?.(hovered ? (hovered === d.selected ? null : hovered) : null) }
    el.addEventListener('mousedown', onDown); window.addEventListener('mouseup', onUp)
    window.addEventListener('mousemove', onMove); el.addEventListener('wheel', onWheel, { passive: false })
    el.addEventListener('click', onClick)

    const nodes = []
    const labelWrap = labelsRef.current

    function rebuild(board, talkers, protocols) {
      nodes.forEach(n => {
        scene.remove(n.mesh); n.soft && scene.remove(n.soft); n.ring && scene.remove(n.ring)
        n.planetRing && scene.remove(n.planetRing)
        n.link && scene.remove(n.link); n.pts && scene.remove(n.pts); n.label?.remove()
      })
      nodes.length = 0
      // Cyberspace-nebula palette: saturated, luminous, electric. These
      // read as glowing bodies in deep space rather than muted rock.
      // Threat tiers override these for hostile hosts.
      const palette = [
        0x00e5ff,  // electric cyan
        0xb14aff,  // neon violet
        0xff2ea6,  // hot magenta
        0x00ffa3,  // spring neon green
        0xffb020,  // amber gold
        0x4d7cff,  // electric blue
        0xff5edb,  // orchid pink
        0x2fe0d0,  // turquoise
        0x8b5cff,  // deep violet
        0xffe14d,  // plasma yellow
        0x00c2ff,  // azure glow
        0xd94aff,  // ultraviolet
      ]

      const byHost = new Map()
      talkers.forEach(t => byHost.set(t.src_ip, t))
      board.forEach(b => { if (!byHost.has(b.host)) byHost.set(b.host, { src_ip: b.host, bytes: 0 }) })
      const list = [...byHost.values()].slice(0, MAX_NODES)
      const maxB = Math.max(1, ...list.map(t => t.bytes || 0))

      list.forEach((t, i) => {
        const host = t.src_ip
        const b = board.find(x => x.host === host)
        const hostile = b && (b.tier === 'critical' || b.tier === 'high')
        const hex = b ? tier(b.tier).int : palette[i % palette.length]
        const radius = (b || t.bytes > 0) ? logScale(t.bytes || 1000, 1000, maxB, 2.2, 7.5) : 1.7

        const mesh = new THREE.Mesh(sphere, matFor(hex))
        mesh.scale.setScalar(radius)
        mesh.userData = { host, radius }
        scene.add(mesh)

        const soft = makeGlow(hex, hostile ? .9 : b ? .55 : .45)
        soft.scale.setScalar(radius * (hostile ? 8 : 4.6)); scene.add(soft)

        let ring = null
        if (hostile) {
          const rp = []
          for (let a = 0; a <= 56; a++) { const th = a / 56 * Math.PI * 2; rp.push(new THREE.Vector3(Math.cos(th) * radius * 2.7, 0, Math.sin(th) * radius * 2.7)) }
          ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(rp),
            new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: .8 }))
          ring.rotation.x = Math.PI / 2.5; scene.add(ring)
        }

        /* larger bodies get a Saturn-style ring — visual variety and it
           encodes "this host carries serious volume" at a glance */
        let planetRing = null
        if (!hostile && radius > 5.2) {
          const rr = []
          for (let a = 0; a <= 72; a++) {
            const th = a / 72 * Math.PI * 2
            rr.push(new THREE.Vector3(Math.cos(th) * radius * 1.9, 0, Math.sin(th) * radius * 1.9))
          }
          planetRing = new THREE.Line(
            new THREE.BufferGeometry().setFromPoints(rr),
            new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: .45 }))
          planetRing.rotation.x = Math.PI / 2 - 0.38
          planetRing.rotation.z = (i % 5) * 0.22
          scene.add(planetRing)
        }

        let link = null, pts = null, pPos = null
        const busy = t.bytes > maxB * .04
        if (b || busy) {
          link = new THREE.Line(
            new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]),
            new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: hostile ? .5 : .18 }))
          scene.add(link)
          pPos = new Float32Array(PPL * 3)
          const pg = new THREE.BufferGeometry()
          pg.setAttribute('position', new THREE.BufferAttribute(pPos, 3))
          pts = new THREE.Points(pg, new THREE.PointsMaterial({
            color: hex, size: hostile ? 3.6 : 2.6, transparent: true, opacity: .95,
            blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true }))
          scene.add(pts)
        }

        let label = null
        if (b || t.bytes > maxB * .08) {
          label = document.createElement('div')
          label.style.cssText = `position:absolute;font:500 9.5px 'IBM Plex Mono',monospace;letter-spacing:.2px;white-space:nowrap;pointer-events:none;color:#${hex.toString(16).padStart(6,'0')};text-shadow:0 0 8px rgba(0,1,5,.99),0 0 3px rgba(0,1,5,.9);will-change:transform`
          label.textContent = shortHost(host)
          labelWrap.appendChild(label)
        }

        const ri = ringFor(host, talkers, maxB)
        nodes.push({ host, hex, mesh, soft, ring, planetRing, link, pts, pPos, label, radius, hostile,
          ang: ((i * 137.508) % 360) * Math.PI / 180,
          inc: (((i * 53) % 100) / 100 - .5) * .36,
          rad: RINGS[ri - 1] * (.9 + ((i * 37) % 20) / 100),
          spd: (.0019 + ((i * 17) % 13) / 10000) / (ri * .8),
          flow: Array.from({ length: PPL }, (_, k) => k / PPL),
          fspd: .005 + (t.bytes / maxB) * .013 })
      })
    }
    rebuild(dataRef.current.board, dataRef.current.talkers, protocols)
    stateRef.current.rebuild = rebuild

    const resize = () => {
      const r = mount.getBoundingClientRect()
      renderer.setSize(r.width, r.height, false)
      camera.aspect = r.width / r.height || 1
      camera.updateProjectionMatrix()
    }
    resize()
    const ro = new ResizeObserver(resize); ro.observe(mount)

    const v = new THREE.Vector3()
    let raf, prev = performance.now(), vis = true
    const onVis = () => { vis = !document.hidden }
    document.addEventListener('visibilitychange', onVis)

    const loop = now => {
      raf = requestAnimationFrame(loop)
      if (!vis) return
      const dt = Math.min(64, now - prev); prev = now
      const k = dt / 16.67, lerp = 1 - Math.pow(.86, k)

      cam.az += (cam.tAz - cam.az) * lerp
      cam.el += (cam.tEl - cam.el) * lerp
      cam.dist += (cam.tDist - cam.dist) * lerp
      applyCam()

      const rect = mount.getBoundingClientRect()
      const { selected } = dataRef.current
      const pulse = reduced ? 1 : 1 + Math.sin(now * .0015) * .08
      core.scale.setScalar(6.5 * pulse); cg1.scale.setScalar(34 * pulse)
      cg2.scale.setScalar(78 * (1 + Math.sin(now * .0011) * .05))
      if (!reduced) corona.rotation.z += .0018 * k
      if (!reduced && stateRef.current.belt) stateRef.current.belt.rotation.y += .0004 * k

      raycaster.setFromCamera(pointer, camera)
      const hits = raycaster.intersectObjects(nodes.map(n => n.mesh), false)
      const nh = hits.length ? hits[0].object.userData.host : null
      if (nh !== hovered) { hovered = nh; onHover?.(hovered); el.style.cursor = hovered ? 'pointer' : (dragging ? 'grabbing' : 'grab') }

      for (const n of nodes) {
        if (!reduced) n.ang += n.spd * k
        const x = Math.cos(n.ang) * n.rad, z = Math.sin(n.ang) * n.rad, y = Math.sin(n.ang) * n.rad * n.inc
        n.mesh.position.set(x, y, z)
        const isSel = selected === n.host, isHov = hovered === n.host, dim = selected && !isSel
        const tg = n.radius * (isSel ? 1.5 : isHov ? 1.25 : 1)
        n.mesh.scale.setScalar(n.mesh.scale.x + (tg - n.mesh.scale.x) * lerp)
        n.mesh.material.opacity = dim ? .3 : 1; n.mesh.material.transparent = dim

        if (n.soft) {
          n.soft.position.set(x, y, z)
          const p = n.hostile && !reduced ? 1 + Math.sin(now * .0032) * .3 : 1
          const g = n.radius * (n.hostile ? 8 : 4.6) * p * (isSel ? 1.45 : 1)
          n.soft.scale.set(g, g, 1)
          n.soft.material.opacity = dim ? .1 : (n.hostile ? .9 : .5)
        }
        if (n.ring) { n.ring.position.set(x, y, z); if (!reduced) n.ring.rotation.z += .013 * k; n.ring.material.opacity = dim ? .16 : .8 }
        if (n.planetRing) { n.planetRing.position.set(x, y, z); n.planetRing.material.opacity = dim ? .1 : .45 }
        if (n.link) {
          const pos = n.link.geometry.attributes.position
          pos.setXYZ(1, x, y, z); pos.needsUpdate = true
          n.link.material.opacity = isSel ? .72 : dim ? .04 : (n.hostile ? .5 : .18)
        }
        if (n.pts && n.pPos) {
          for (let i = 0; i < PPL; i++) {
            if (!reduced) { n.flow[i] += n.fspd * k; if (n.flow[i] > 1) n.flow[i] -= 1 }
            const f = 1 - n.flow[i]
            n.pPos[i * 3] = x * f; n.pPos[i * 3 + 1] = y * f; n.pPos[i * 3 + 2] = z * f
          }
          n.pts.geometry.attributes.position.needsUpdate = true
          n.pts.material.opacity = dim ? .07 : isSel ? 1 : .85
        }
        if (n.label) {
          v.set(x, y, z).project(camera)
          const sx = (v.x * .5 + .5) * rect.width, sy = (-v.y * .5 + .5) * rect.height
          // strict clipping: labels must sit fully inside the panel, with
          // margins that clear the HUD overlay text top and bottom
          const PAD_T = 34, PAD_B = 42, PAD_L = 6, PAD_R = 96
          // when zoomed far out, only show labels for scored/large bodies —
          // otherwise the wide view becomes a wall of overlapping text
          // Label budget scales with zoom: close in, show everything; far
          // out, only the bodies that matter. Keeps a dense system readable.
          const worthLabel = isSel || isHov || n.hostile
            || cam.dist < 260
            || (cam.dist < 420 && n.radius > 3.6)
            || n.radius > 5.4
          const inside = v.z < 1 && worthLabel
            && sx > PAD_L && sx < rect.width - PAD_R
            && sy > PAD_T && sy < rect.height - PAD_B
          n.label.style.display = inside ? 'block' : 'none'
          if (inside) {
            n.label.style.transform = `translate3d(${(sx + n.radius + 7).toFixed(1)}px, ${(sy - 5).toFixed(1)}px, 0)`
            n.label.style.opacity = dim ? '0.25' : '1'
            n.label.style.fontWeight = isSel ? '700' : '500'
          }
        }
      }
      renderer.render(scene, camera)
    }
    raf = requestAnimationFrame(loop)

    return () => {
      cancelAnimationFrame(raf); ro.disconnect()
      document.removeEventListener('visibilitychange', onVis)
      el.removeEventListener('mousedown', onDown); window.removeEventListener('mouseup', onUp)
      window.removeEventListener('mousemove', onMove); el.removeEventListener('wheel', onWheel)
      el.removeEventListener('click', onClick)
      nodes.forEach(n => n.label?.remove())
      sphere.dispose(); glowTex.dispose(); matCache.forEach(m => m.dispose())
      renderer.dispose(); el.remove()
    }
  }, [])

  const sig = board.map(b => `${b.host}:${b.tier}`).join('|') + '#' + talkers.map(t => t.src_ip).join('|')
  useEffect(() => { stateRef.current.rebuild?.(board, talkers, protocols) }, [sig])

  const hostile = board.filter(b => b.tier === 'critical' || b.tier === 'high').length
  return (
    <div ref={mountRef} className="absolute inset-0 overflow-hidden"
         role="img"
         aria-label={`Orbital network map. ${talkers.length} hosts tracked across `
           + `five trust-boundary orbits, ${board.length} scored, ${hostile} hostile. `
           + `Node size encodes traffic volume, colour encodes threat tier.`}>
      <div ref={labelsRef} className="absolute inset-0 pointer-events-none overflow-hidden" />
    </div>
  )
}
