import { useState } from 'react'
import './App.css'
import heroImage from './assets/hero.png'

const navItems = [
  ['DB', 'Dashboard'],
  ['CS', 'Investigations'],
  ['EV', 'Evidence'],
  ['TL', 'Timeline'],
  ['CR', 'Correlation'],
  ['AP', 'Attack Path'],
  ['FN', 'Findings'],
  ['TC', 'Techniques'],
  ['RP', 'Reports'],
]

const stats = [
  ['Investigations', '28', '+4', '82'],
  ['Evidence items', '1,486', '97%', '96'],
  ['Suspicious events', '342', '+61', '74'],
  ['Model confidence', '91%', 'High', '91'],
]

const timeline = [
  ['14:02:11', 'Failed login burst', 'auth.log', 'T1110', 'high'],
  ['14:03:04', 'Valid account established', 'web-01', 'T1078', 'critical'],
  ['14:04:21', 'Payload uploaded through form', 'access.log', 'T1190', 'critical'],
  ['14:05:12', 'Command execution detected', 'process tree', 'T1059', 'critical'],
  ['14:07:45', 'Database table enumerated', 'db-audit', 'T1005', 'high'],
  ['14:09:31', 'Outbound transfer to new host', 'traffic.pcap', 'T1041', 'critical'],
]

const cases = [
  ['#2026-001', 'Web Server Compromise', 'Investigating', 'Critical', '73 items'],
  ['#2026-014', 'Credential Stuffing', 'Active', 'High', '41 items'],
  ['#2026-018', 'Insider Data Access', 'Review', 'Medium', '22 items'],
]

const evidence = [
  ['auth.log', 'System log', 'Analyzed'],
  ['traffic.pcap', 'Network', 'Analyzed'],
  ['events.json', 'Security', 'Processing'],
  ['web-access.log', 'Web', 'Analyzed'],
]

const techniques = [
  ['T1110', 'Brute Force', 88],
  ['T1059', 'Command Interpreter', 74],
  ['T1078', 'Valid Accounts', 66],
  ['T1190', 'Public App Exploit', 81],
]

const findings = [
  ['Critical', 'Remote command execution', '14:05:12'],
  ['High', 'SQL injection pattern', '14:04:21'],
  ['High', 'External exfiltration channel', '14:09:31'],
]

const homeFeatures = [
  ['Evidence Intake', 'Preserve logs, network captures, memory exports, and analyst notes with verifiable custody metadata.'],
  ['Attack Storyline', 'Build a readable sequence from noisy artifacts, mapped to assets, techniques, timestamps, and confidence.'],
  ['Court-Ready Output', 'Convert findings into structured reports that show what happened, how it happened, and what to fix next.'],
]

function App() {
  const [showDashboard, setShowDashboard] = useState(false)

  if (!showDashboard) {
    return (
      <main className="home-shell">
        <section className="home-page home-page-standalone" id="home" aria-labelledby="home-title">
          <div className="home-hero">
            <div className="home-copy">
              <p className="eyebrow">Digital crime scene investigation platform</p>
              <h1 id="home-title">Reconstruct cyber attacks with clarity, evidence, and speed.</h1>
              <p className="home-lede">
                A beautiful forensic workspace for transforming scattered security artifacts into a complete
                incident narrative. Follow the intruder from first contact to impact, validate every clue,
                and prepare a professional report without losing the chain of custody.
              </p>
              <div className="home-actions">
                <button className="home-button primary-link" type="button" onClick={() => setShowDashboard(true)}>
                  Open Dashboard
                </button>
                <button className="home-button ghost-link" type="button" onClick={() => setShowDashboard(true)}>
                  Explore Cases
                </button>
              </div>
            </div>

            <div className="home-visual" aria-label="Digital forensic investigation preview">
              <img src={heroImage} alt="Forensic analyst examining a digital crime scene interface" />
              <div className="home-visual-card">
                <span>Active case</span>
                <strong>Web Server Compromise</strong>
                <small>91% attack path confidence</small>
              </div>
              <div className="home-orbit one" aria-hidden="true"></div>
              <div className="home-orbit two" aria-hidden="true"></div>
            </div>
          </div>

          <div className="home-feature-grid" aria-label="Platform capabilities">
            {homeFeatures.map(([title, description]) => (
              <article className="home-feature" key={title}>
                <span>{title}</span>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark">DF</div>
          <div>
            <span>Digital Forensics</span>
            <strong>Reconstruction Engine</strong>
          </div>
        </div>

        <nav>
          {navItems.map(([icon, label], index) => (
            <a className={index === 0 ? 'active' : ''} href={`#${label.toLowerCase().replace(' ', '-')}`} key={label}>
              <span>{icon}</span>
              {label}
            </a>
          ))}
        </nav>

        <div className="case-lock">
          <span>Chain of custody</span>
          <strong>Verified across 1,486 artifacts</strong>
          <div className="hash-preview">8f2a91bc: locked</div>
          <div className="signal-bars" aria-hidden="true">
            <i></i>
            <i></i>
            <i></i>
            <i></i>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Case #2026-001 / Web server compromise / Active reconstruction</p>
            <h1>Digital Crime Scene Command Center</h1>
          </div>
          <div className="top-actions">
            <button type="button">Import Evidence</button>
            <button type="button">Run Correlation</button>
            <button type="button" className="primary">New Investigation</button>
          </div>
        </header>

        <section className="intel-strip" aria-label="Current incident summary">
          <div>
            <span>Attack duration</span>
            <strong>7m 20s</strong>
          </div>
          <div>
            <span>Primary source</span>
            <strong>192.168.1.25</strong>
          </div>
          <div>
            <span>Affected assets</span>
            <strong>Web, DB, Auth</strong>
          </div>
          <div>
            <span>Report readiness</span>
            <strong>84%</strong>
          </div>
        </section>

        <section className="hero-grid" id="dashboard">
          <div className="hero-panel">
            <div className="scanline" aria-hidden="true"></div>
            <div className="hero-copy">
              <p className="eyebrow">Investigator workflow</p>
              <h2>Turn scattered logs into a reconstructed attack story.</h2>
              <p>
                Import evidence, preserve integrity, correlate events across
                sources, visualize attacker movement, and generate a forensic
                report from one polished analyst workspace.
              </p>
            </div>

            <div className="stats-grid">
              {stats.map(([label, value, note, level]) => (
                <article className="stat-card" key={label}>
                  <span>{label}</span>
                  <strong>{value}</strong>
                  <small>{note}</small>
                  <div className="meter" aria-hidden="true">
                    <i style={{ width: `${level}%` }}></i>
                  </div>
                </article>
              ))}
            </div>
          </div>

          <div className="reconstruction-panel" id="attack-path" aria-label="Attack reconstruction graph">
            <div className="panel-heading">
              <div>
                <span>Live reconstruction model</span>
                <strong>Attack path confidence 91%</strong>
              </div>
              <button type="button">Inspect</button>
            </div>
            <div className="graph-stage">
              <div className="radar-ring one" aria-hidden="true"></div>
              <div className="radar-ring two" aria-hidden="true"></div>
              <div className="node attacker"><small>External</small>Attacker</div>
              <div className="node ip"><small>Source IP</small>192.168.1.25</div>
              <div className="node server"><small>Asset</small>Web Server</div>
              <div className="node exploit"><small>Technique</small>Exploit</div>
              <div className="node shell"><small>Process</small>Reverse Shell</div>
              <div className="node db"><small>Target</small>Database</div>
              <div className="node data"><small>Impact</small>Sensitive Data</div>
              <svg viewBox="0 0 620 420" role="presentation" aria-hidden="true">
                <path d="M70 92 C132 42, 180 98, 232 88" />
                <path d="M278 104 C338 120, 384 86, 454 124" />
                <path d="M476 154 C438 202, 396 218, 346 242" />
                <path d="M322 270 C256 286, 214 260, 156 316" />
                <path d="M368 278 C418 322, 476 332, 530 292" />
                <path d="M502 164 C548 196, 562 232, 534 270" />
              </svg>
            </div>
          </div>
        </section>

        <section className="content-grid">
          <article className="module large" id="timeline">
            <div className="section-title">
              <div>
                <p className="eyebrow">Incident timeline</p>
                <h3>Reconstructed sequence</h3>
              </div>
              <span className="pill">6 linked moments</span>
            </div>
            <div className="timeline">
              {timeline.map(([time, title, source, technique, severity]) => (
                <div className={`timeline-row ${severity}`} key={time}>
                  <time>{time}</time>
                  <span className="timeline-dot"></span>
                  <div>
                    <strong>{title}</strong>
                    <small>{source} / {technique}</small>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="module" id="evidence">
            <div className="section-title">
              <div>
                <p className="eyebrow">Evidence vault</p>
                <h3>Collection queue</h3>
              </div>
              <span className="pill">SHA-256</span>
            </div>
            <div className="evidence-list">
              {evidence.map(([file, type, status]) => (
                <div key={file}>
                  <span>{file}<small>{type}</small></span>
                  <strong>{status}</strong>
                </div>
              ))}
            </div>
          </article>

          <article className="module cases" id="investigations">
            <div className="section-title">
              <div>
                <p className="eyebrow">Investigations</p>
                <h3>Recent cases</h3>
              </div>
              <button type="button">View all</button>
            </div>
            <div className="case-table">
              {cases.map(([id, name, status, severity, items]) => (
                <div className="case-row" key={id}>
                  <strong>{id}</strong>
                  <span>{name}</span>
                  <em>{status}</em>
                  <b>{severity}</b>
                  <small>{items}</small>
                </div>
              ))}
            </div>
          </article>

          <article className="module" id="findings">
            <div className="section-title">
              <div>
                <p className="eyebrow">Suspicious findings</p>
                <h3>Priority queue</h3>
              </div>
            </div>
            <div className="finding-list">
              {findings.map(([severity, title, time]) => (
                <div key={title}>
                  <b>{severity}</b>
                  <span>{title}</span>
                  <time>{time}</time>
                </div>
              ))}
            </div>
          </article>

          <article className="module" id="techniques">
            <div className="section-title">
              <div>
                <p className="eyebrow">MITRE ATT&CK</p>
                <h3>Detected techniques</h3>
              </div>
            </div>
            <div className="technique-list">
              {techniques.map(([id, label, level]) => (
                <div key={id}>
                  <span><strong>{id}</strong>{label}</span>
                  <div className="meter" aria-hidden="true">
                    <i style={{ width: `${level}%` }}></i>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="module report" id="reports">
            <div className="section-title">
              <div>
                <p className="eyebrow">Reports</p>
                <h3>Forensic report preview</h3>
              </div>
              <span className="pill">PDF / JSON / CSV</span>
            </div>
            <div className="report-sheet">
              <strong>Digital Forensic Investigation Report</strong>
              <ol>
                <li>Executive Summary</li>
                <li>Evidence Analyzed</li>
                <li>Incident Timeline</li>
                <li>Attack Reconstruction</li>
                <li>Findings and Recommendations</li>
              </ol>
            </div>
          </article>
        </section>
      </section>
    </main>
  )
}

export default App
