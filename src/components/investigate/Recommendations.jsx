import './Recommendations.css'

const PRIORITIES = ['IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW']

export default function Recommendations({ recommendations = [] }) {
  if (recommendations.length === 0) return null

  // Global index counter for 01, 02, 03... numbering
  let globalIndex = 1

  const grouped = PRIORITIES.map(priority => {
    const items = recommendations
      .filter(r => (r.priority || '').toUpperCase() === priority)
      .map(r => ({
        ...r,
        numStr: String(globalIndex++).padStart(2, '0'),
      }))
    return { priority, items }
  }).filter(g => g.items.length > 0)

  return (
    <div className="recommendations-panel" id="recommendations-section">
      <div className="recommendations-header-row">
        <h3 className="rec-panel-title">RECOMMENDED INVESTIGATION</h3>
        <span className="rec-panel-sub font-mono">{recommendations.length} containment actions</span>
      </div>

      <div className="priority-groups-list">
        {grouped.map(({ priority, items }) => (
          <div key={priority} className="priority-group">
            <div className="priority-group-header font-mono">
              <span className={`priority-tag tag-${priority.toLowerCase()}`}>{priority}</span>
            </div>

            <div className="priority-items-list">
              {items.map(rec => (
                <div key={rec.id || rec.numStr} className="rec-compact-row">
                  <span className="rec-seq-num font-mono">{rec.numStr}</span>
                  <div className="rec-main-info">
                    <div className="rec-action-title">{rec.action}</div>
                    {rec.reason && (
                      <div className="rec-action-reason">{rec.reason}</div>
                    )}
                  </div>
                  {rec.relatedFindings?.length > 0 && (
                    <div className="rec-ref-tags">
                      {rec.relatedFindings.slice(0, 1).map(fid => (
                        <span key={fid} className="rec-fid-tag font-mono">{fid}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
