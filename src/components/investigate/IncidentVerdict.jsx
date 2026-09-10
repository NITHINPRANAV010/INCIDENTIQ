import './IncidentVerdict.css'

function getSeverityClass(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'info'
  }
}

export default function IncidentVerdict({ verdict }) {
  if (!verdict) return null

  const { severity, incidentType, confidence, summary, keyIndicators = [] } = verdict
  const sevClass     = getSeverityClass(severity)
  const confidenceInt = Math.round(confidence || 0)

  return (
    <div className={`verdict-card verdict-${sevClass} animate-fade-in`} id="incident-verdict">
      <div className="verdict-top-label">Incident Verdict</div>

      <div className="verdict-main-row">
        <span className={`verdict-badge badge-${sevClass}`}>{severity}</span>
        <span className="verdict-confidence-badge font-mono">{confidenceInt}% confidence</span>
      </div>

      <h3 className="verdict-title">{incidentType}</h3>

      {summary && (
        <p className="verdict-summary-text">{summary}</p>
      )}

      {keyIndicators.length > 0 && (
        <div className="verdict-indicators-section">
          <div className="indicators-header-label">Key Indicators</div>
          <div className="indicators-chip-list">
            {keyIndicators.map((ind, i) => (
              <div key={i} className="indicator-chip">
                <span className={`status-dot dot-${sevClass}`} />
                <span className="indicator-name">{ind}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
