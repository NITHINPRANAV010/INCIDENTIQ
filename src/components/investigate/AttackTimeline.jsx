import './AttackTimeline.css'

function getSeverityClass(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'info'
  }
}

export default function AttackTimeline({ timeline = [], highlightedEventId = null, onEventClick = null }) {
  if (timeline.length === 0) return null

  return (
    <div className="timeline-section-panel" id="timeline-section">
      <div className="timeline-header-row">
        <h3 className="timeline-title">Attack Timeline</h3>
        <span className="timeline-event-count font-mono">{timeline.length} events</span>
      </div>

      <div className="forensic-timeline">
        {timeline.map((event, idx) => {
          const sevClass = getSeverityClass(event.severity)
          const isLast  = idx === timeline.length - 1
          const timeStr = event.displayTime || event.timestamp || '—'
          const isTargeted = highlightedEventId && highlightedEventId === event.eventId

          return (
            <div
              key={event.eventId || idx}
              id={`timeline-event-${event.eventId}`}
              className={`timeline-forensic-row ${isTargeted ? 'timeline-row-targeted' : ''}`}
            >
              {/* Timestamp */}
              <div className="timeline-time-col font-mono">{timeStr}</div>

              {/* Dot + line */}
              <div className="timeline-line-col">
                <span className={`timeline-dot dot-${sevClass}`} />
                {!isLast && <div className="timeline-line" />}
              </div>

              {/* Content */}
              <div className="timeline-entry-content">
                <span className="timeline-entry-desc">{event.description}</span>
                {event.eventId && (
                  <button
                    type="button"
                    className="event-id font-mono timeline-id-btn"
                    onClick={() => onEventClick?.(event.eventId)}
                    title={`Click to inspect event ${event.eventId} in Evidence Ledger`}
                  >
                    {event.eventId}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
