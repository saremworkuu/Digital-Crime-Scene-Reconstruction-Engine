const statCards = [
  { label: 'Open cases', value: '28', delta: '+4 this week' },
  { label: 'Evidence items', value: '1,486', delta: '97% processed' },
  { label: 'Threat events', value: '342', delta: '61 flagged' },
  { label: 'Confidence', value: '91%', delta: 'High confidence' },
]

const timeline = [
  { time: '14:02:11', event: 'Failed login burst', type: 'auth.log', severity: 'High' },
  { time: '14:03:04', event: 'Valid account established', type: 'web-01', severity: 'Critical' },
  { time: '14:04:21', event: 'Payload uploaded via form', type: 'access.log', severity: 'Critical' },
  { time: '14:05:12', event: 'Command execution detected', type: 'process tree', severity: 'High' },
]

const alerts = [
  { title: 'Remote command execution', severity: 'Critical', time: '14:05:12' },
  { title: 'SQL injection pattern', severity: 'High', time: '14:04:21' },
  { title: 'Outbound transfer to unknown host', severity: 'Critical', time: '14:09:31' },
]

export default function Dashboard() {
  return (
    <div className="dashboard-page">
      <section className="stats-grid">
        {statCards.map((card) => (
          <article key={card.label} className="stat-card">
            <span>{card.label}</span>
            <strong>{card.value}</strong>
            <small>{card.delta}</small>
          </article>
        ))}
      </section>

      <section className="dashboard-grid">
        <div className="panel large-panel">
          <div className="panel-header">
            <h3>Investigation timeline</h3>
            <button type="button" className="ghost-btn small-btn">Export</button>
          </div>

          <div className="timeline-list">
            {timeline.map((item) => (
              <div key={`${item.time}-${item.event}`} className="timeline-item">
                <span className="time">{item.time}</span>
                <div className="timeline-content">
                  <strong>{item.event}</strong>
                  <small>{item.type}</small>
                </div>
                <span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h3>Priority alerts</h3>
          </div>

          <div className="alert-list">
            {alerts.map((alert) => (
              <div key={alert.title} className="alert-item">
                <div>
                  <strong>{alert.title}</strong>
                  <small>{alert.time}</small>
                </div>
                <span className={`severity ${alert.severity.toLowerCase()}`}>{alert.severity}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
