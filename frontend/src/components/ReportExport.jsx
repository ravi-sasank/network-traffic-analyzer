import { useState } from 'react'

/**
 * Report download controls. Generation runs server-side and can take a
 * moment on a large capture, so each button shows its own progress state
 * rather than leaving the user wondering whether the click registered.
 */
function useDownload() {
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)

  const grab = async (kind, path, ext) => {
    setBusy(kind)
    setError(null)
    try {
      const res = await fetch(path)
      if (!res.ok) throw new Error(`server returned ${res.status}`)
      const blob = await res.blob()
      // prefer the filename the server supplies, fall back to a dated one
      const cd = res.headers.get('Content-Disposition') || ''
      const match = /filename="?([^";]+)"?/.exec(cd)
      const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')
      const name = match ? match[1] : `sentinel-report-${stamp}.${ext}`

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = name
      document.body.appendChild(a)
      a.click()
      a.remove()
      // give the browser a beat before revoking, or Safari cancels the save
      setTimeout(() => URL.revokeObjectURL(url), 1500)
    } catch (e) {
      setError(String(e.message || e))
      setTimeout(() => setError(null), 5000)
    } finally {
      setBusy(null)
    }
  }
  return { busy, error, grab }
}

const ICON = {
  pdf: 'M4 1.5h5.5L13 5v9.5H4V1.5Z M9.5 1.5V5H13',
  xls: 'M2.5 2.5h11v11h-11v-11Z M2.5 6.2h11 M6.2 2.5v11',
}

function ExportButton({ label, sub, kind, busy, onClick, accent }) {
  const isBusy = busy === kind
  return (
    <button
      onClick={onClick}
      disabled={!!busy}
      title={`Download ${label}`}
      className="w-full flex items-center gap-[9px] px-[10px] py-[8px] mb-[6px] last:mb-0
                 border border-[#1b2a44] bg-[#0a1120] text-left
                 transition-all duration-200 disabled:opacity-50"
      style={{ borderLeftWidth: 2, borderLeftColor: accent }}
    >
      <div className="w-[24px] h-[24px] flex items-center justify-center flex-shrink-0
                      border rounded-[2px]"
           style={{ borderColor: `${accent}66`, background: `${accent}14`, color: accent }}>
        {isBusy ? (
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none"
               style={{ animation: 'spin 0.8s linear infinite' }}>
            <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.6"
                    strokeDasharray="28" strokeDashoffset="10" strokeLinecap="round" />
          </svg>
        ) : (
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
            <path d={ICON[kind]} stroke="currentColor" strokeWidth="1.3"
                  strokeLinejoin="round" />
          </svg>
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-[10.5px] font-semibold text-[#e8eff8] tracking-[.3px]">
          {isBusy ? 'Generating…' : label}
        </div>
        <div className="text-[8px] text-[#6b7f99] tracking-[.8px] mt-[2px]">{sub}</div>
      </div>
      {!isBusy && (
        <svg width="11" height="11" viewBox="0 0 16 16" fill="none"
             className="flex-shrink-0" style={{ color: '#6b7f99' }}>
          <path d="M8 2v9M4.5 7.5 8 11l3.5-3.5M2.5 13.5h11"
                stroke="currentColor" strokeWidth="1.3"
                strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </button>
  )
}

export default function ReportExport() {
  const { busy, error, grab } = useDownload()
  return (
    <>
      <ExportButton
        label="Security report" sub="PDF · FULL ASSESSMENT"
        kind="pdf" busy={busy} accent="#ff5470"
        onClick={() => grab('pdf', '/api/report/pdf', 'pdf')} />
      <ExportButton
        label="Data workbook" sub="XLSX · 9 SHEETS"
        kind="xls" busy={busy} accent="#4ee8a8"
        onClick={() => grab('xls', '/api/report/excel', 'xlsx')} />
      {error && (
        <div className="mt-[6px] text-[8.5px] text-[#ff5470] leading-[1.5]">
          Export failed: {error}
        </div>
      )}
      <div className="mt-[8px] pt-[8px] border-t border-[#1b2a448c]
                      text-[8px] text-[#6b7f99] leading-[1.6]">
        Reports are generated from the live capture database at the moment of download.
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </>
  )
}
