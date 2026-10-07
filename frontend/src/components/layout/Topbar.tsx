export default function Topbar() {
  return (
    <header className="topbar">
      <div>
        <span className="eyebrow">Investigation workspace</span>
        <h1>Digital Crime Scene Reconstruction Engine</h1>
      </div>

      <div className="topbar-actions">
        <button type="button" className="ghost-btn">Import evidence</button>
        <button type="button" className="primary-btn">New case</button>
      </div>
    </header>
  )
}
