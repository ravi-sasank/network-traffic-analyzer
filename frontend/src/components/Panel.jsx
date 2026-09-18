export default function Panel({ title, meta, children, className = '', bodyClass = '' }) {
  return (
    <div className={`flex flex-col min-h-0 border-b border-[#1b2a44] ${className}`}>
      <div className="panel-head">
        <h2 className="panel-title">{title}</h2>
        {meta && <span className="panel-meta">{meta}</span>}
      </div>
      <div className={`panel-body ${bodyClass}`}>{children}</div>
    </div>
  )
}
