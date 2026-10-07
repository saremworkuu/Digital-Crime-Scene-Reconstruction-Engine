import { Link } from 'react-router-dom'

const capabilities = [
  {
    title: 'Evidence Intake',
    description:
      'Capture system logs, network captures, memory artifacts, and case notes with tamper-aware chain-of-custody tracking.',
  },
  {
    title: 'Attack Reconstruction',
    description:
      'Map suspicious activity across hosts, accounts, and services to reconstruct a coherent timeline of compromise.',
  },
  {
    title: 'Actionable Reporting',
    description:
      'Transform raw forensic data into confident, court-ready summaries with evidence-backed findings and indicators.',
  },
]

const metrics = [
  { label: 'Open investigations', value: '28' },
  { label: 'Artifacts processed', value: '1.4K' },
  { label: 'Threat confidence', value: '91%' },
  { label: 'Avg. review time', value: '7 min' },
]

export default function Home() {
  return (
    <div className="home-page">
      <header className="home-header">
        <div className="nav-shell">
          <div className="brand-home">
            <div className="brand-mark">D</div>
            <span>DCSRE</span>
          </div>

          <nav className="home-nav">
            <a href="#platform">Platform</a>
            <a href="#capabilities">Capabilities</a>
            <a href="#security">Security</a>
          </nav>

          <div className="home-actions">
            <Link to="/login" className="ghost-btn">Login</Link>
            <Link to="/register" className="primary-btn">Register</Link>
          </div>
        </div>
      </header>

      <main className="home-body">
        <section className="hero-section">
          <div className="hero-copy">
            <span className="eyebrow">Digital forensic intelligence platform</span>
            <h1>Reconstruct cyber incidents with clarity, confidence, and speed.</h1>
            <p>
              DCSRE helps security teams transform fragmented evidence into a complete digital crime scene narrative — from the first suspicious login to the final exfiltration event.
            </p>

            <div className="cta-row">
              <Link to="/register" className="primary-btn large-btn">Create account</Link>
              <Link to="/login" className="ghost-btn large-btn">Sign in</Link>
            </div>

            <div className="trust-row">
              {metrics.map((metric) => (
                <div key={metric.label} className="metric-box">
                  <strong>{metric.value}</strong>
                  <span>{metric.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="hero-visual">
            <div className="glass-panel highlight-panel">
              <div className="panel-topline">
                <span>Case #2026-001</span>
                <span className="status-pill">Active</span>
              </div>
              <h3>Web Server Compromise</h3>
              <div className="mini-chart" aria-hidden="true">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
              </div>
              <ul>
                <li>Failed login burst detected</li>
                <li>Privilege escalation confirmed</li>
                <li>Exfiltration route mapped</li>
              </ul>
            </div>
          </div>
        </section>

        <section id="platform" className="feature-band">
          <div className="section-heading">
            <span className="eyebrow">Built for investigators</span>
            <h2>Everything needed to investigate, correlate, and report.</h2>
          </div>

          <div className="feature-grid">
            {capabilities.map((capability) => (
              <article key={capability.title} className="feature-card">
                <div className="feature-icon">✦</div>
                <h3>{capability.title}</h3>
                <p>{capability.description}</p>
              </article>
            ))}
          </div>
        </section>

        <section id="security" className="security-band">
          <div className="security-copy">
            <span className="eyebrow">Security-first workflow</span>
            <h2>From raw evidence to a defensible narrative.</h2>
            <p>
              Protect your investigation chain, validate artifact integrity, and share findings with legal, compliance, and incident response teams using a single trusted workspace.
            </p>
          </div>

          <div className="security-list">
            <div>
              <strong>Chain of custody</strong>
              <span>Artifact integrity tracking and evidence validation</span>
            </div>
            <div>
              <strong>Timeline correlation</strong>
              <span>Multi-source event fusion with context-rich analysis</span>
            </div>
            <div>
              <strong>Report generation</strong>
              <span>Actionable summaries ready for stakeholders and legal review</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}
