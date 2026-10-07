import { NavLink } from 'react-router-dom'

const items = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/dashboard/cases', label: 'Cases' },
  { to: '/dashboard/evidence', label: 'Evidence' },
  { to: '/dashboard/timeline', label: 'Timeline' },
  { to: '/dashboard/attack-graph', label: 'Attack Graph' },
  { to: '/dashboard/detections', label: 'Detections' },
  { to: '/dashboard/reports', label: 'Reports' },
  { to: '/dashboard/audit-log', label: 'Audit Log' },
  { to: '/dashboard/users', label: 'Users' },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-mark">D</div>
        <div>
          <span className="brand-label">Digital Forensics</span>
          <strong>DCSRE</strong>
        </div>
      </div>

      <nav className="side-nav">
        {items.map((item) => (
          <NavLink key={item.to} to={item.to} className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}>
            <span className="nav-dot" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-card">
        <span>Case integrity</span>
        <strong>Verified chain of custody</strong>
        <small>4.7 TB forensic archive</small>
      </div>
    </aside>
  )
}
