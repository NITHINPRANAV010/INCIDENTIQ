import { useState, useMemo } from 'react'
import { FileText, Search, ChevronDown, ChevronUp, Shield, Terminal, Globe, Key, AlertTriangle } from 'lucide-react'
import './EvidenceLedger.css'

function getEventIcon(eventType) {
  const t = (eventType || '').toLowerCase()
  if (t.includes('auth')) return <Key size={12} className="ev-type-icon text-accent" />
  if (t.includes('net') || t.includes('c2') || t.includes('transfer')) return <Globe size={12} className="ev-type-icon text-cyan" />
  if (t.includes('priv') || t.includes('sudo') || t.includes('proc')) return <Terminal size={12} className="ev-type-icon text-warning" />
  if (t.includes('alert') || t.includes('malware')) return <AlertTriangle size={12} className="ev-type-icon text-critical" />
  return <Shield size={12} className="ev-type-icon text-muted" />
}

export default function EvidenceLedger({ events = [], highlightedEventId = null }) {
  const [filterType, setFilterType] = useState('ALL')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedRaws, setExpandedRaws] = useState({})
  const [isCollapsed, setIsCollapsed] = useState(false)

  const toggleRaw = (id) => {
    setExpandedRaws(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const filteredEvents = useMemo(() => {
    return (events || []).filter(ev => {
      // Type filter
      if (filterType !== 'ALL') {
        const t = (ev.eventType || '').toLowerCase()
        const id = (ev.eventId || '').toLowerCase()
        if (filterType === 'AUTH' && !t.includes('auth') && !id.startsWith('auth')) return false
        if (filterType === 'NETWORK' && !t.includes('net') && !t.includes('transfer') && !id.startsWith('net')) return false
        if (filterType === 'ENDPOINT' && !t.includes('priv') && !t.includes('proc') && !t.includes('sudo') && !id.startsWith('proc')) return false
        if (filterType === 'ALERT' && !t.includes('alert') && !id.startsWith('alert') && !id.startsWith('ids')) return false
      }

      // Search term
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase()
        const matchId = (ev.eventId || '').toLowerCase().includes(q)
        const matchUser = (ev.username || '').toLowerCase().includes(q)
        const matchSrcIp = (ev.sourceIp || '').toLowerCase().includes(q)
        const matchDstIp = (ev.destinationIp || '').toLowerCase().includes(q)
        const matchMsg = (ev.message || '').toLowerCase().includes(q)
        const matchRaw = (ev.raw || '').toLowerCase().includes(q)
        const matchFile = (ev.evidenceFile || '').toLowerCase().includes(q)
        return matchId || matchUser || matchSrcIp || matchDstIp || matchMsg || matchRaw || matchFile
      }

      return true
    })
  }, [events, filterType, searchTerm])

  if (!events || events.length === 0) return null

  return (
    <div className="evidence-ledger-panel animate-fade-in" id="evidence-ledger">
      {/* Header Bar */}
      <div className="ledger-header">
        <div className="ledger-title-group">
          <span className="ledger-title">INGESTED EVIDENCE LEDGER</span>
          <span className="ledger-count font-mono">{events.length} Normalized Events</span>
          {highlightedEventId && (
            <span className="ledger-active-target font-mono animate-pulse">
              Targeted: {highlightedEventId}
            </span>
          )}
        </div>

        <div className="ledger-controls">
          <div className="ledger-search-box">
            <Search size={11} className="search-icon" />
            <input
              type="text"
              className="ledger-search-input font-mono"
              placeholder="Filter by ID, IP, user, payload..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
          </div>

          <button
            className="btn btn-ghost btn-xs ledger-toggle-btn font-mono"
            onClick={() => setIsCollapsed(c => !c)}
            aria-expanded={!isCollapsed}
          >
            <span>{isCollapsed ? 'EXPAND LEDGER ▾' : 'COLLAPSE ▴'}</span>
          </button>
        </div>
      </div>

      {!isCollapsed && (
        <>
          {/* Filter Pills */}
          <div className="ledger-filter-row">
            {['ALL', 'AUTH', 'NETWORK', 'ENDPOINT', 'ALERT'].map(type => (
              <button
                key={type}
                className={`ledger-filter-chip font-mono ${filterType === type ? 'active' : ''}`}
                onClick={() => setFilterType(type)}
              >
                {type}
              </button>
            ))}
            <span className="ledger-filter-stats font-mono">
              Showing {filteredEvents.length} of {events.length}
            </span>
          </div>

          {/* Events Table / List */}
          <div className="ledger-table-wrapper">
            <div className="ledger-list">
              {filteredEvents.map((ev, idx) => {
                const isTarget = highlightedEventId === ev.eventId
                const rawOpen = expandedRaws[ev.eventId] || isTarget

                return (
                  <div
                    key={ev.eventId || idx}
                    id={`evidence-event-${ev.eventId}`}
                    className={`ledger-row ${isTarget ? 'ledger-row-targeted' : ''}`}
                  >
                    <div className="ledger-row-main">
                      {/* Event ID and Time */}
                      <div className="ledger-col-id">
                        <span className="event-id font-mono">{ev.eventId}</span>
                        <span className="ledger-time font-mono">
                          {ev.timestamp ? ev.timestamp.split('T')[1]?.replace('Z', '') || ev.timestamp : '—'}
                        </span>
                      </div>

                      {/* Source & File */}
                      <div className="ledger-col-source">
                        <div className="ledger-source-badge font-mono" title={`Origin file: ${ev.evidenceFile}`}>
                          <FileText size={10} style={{ marginRight: 4 }} />
                          <span>{ev.evidenceFile || ev.source || 'telemetry'}</span>
                        </div>
                        <div className="ledger-type-badge font-mono">
                          {getEventIcon(ev.eventType)}
                          <span>{ev.eventType || 'event'}</span>
                        </div>
                      </div>

                      {/* Key Entities: User, IPs, Process */}
                      <div className="ledger-col-entities font-mono">
                        {ev.username && (
                          <span className="entity-chip entity-user" title="Principal Username">
                            user: <strong>{ev.username}</strong>
                          </span>
                        )}
                        {ev.sourceIp && (
                          <span className="entity-chip entity-ip" title="Source IP">
                            src: <strong>{ev.sourceIp}</strong>
                            {ev.port ? `:${ev.port}` : ''}
                          </span>
                        )}
                        {ev.destinationIp && (
                          <span className="entity-chip entity-ip" title="Destination IP">
                            dst: <strong>{ev.destinationIp}</strong>
                          </span>
                        )}
                        {ev.process && (
                          <span className="entity-chip entity-proc" title="Command/Binary">
                            proc: <strong>{ev.process}</strong>
                          </span>
                        )}
                      </div>

                      {/* Summary Message */}
                      <div className="ledger-col-msg">
                        <span className="ledger-msg-text">{ev.message || ev.action || 'Telemetry record'}</span>
                      </div>

                      {/* Raw Evidence Toggle Button */}
                      <div className="ledger-col-actions">
                        <button
                          className="btn btn-ghost btn-xs raw-toggle-btn font-mono"
                          onClick={() => toggleRaw(ev.eventId)}
                          title="Inspect raw log evidence"
                        >
                          <span>RAW</span>
                          {rawOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                        </button>
                      </div>
                    </div>

                    {/* Raw Evidence Drawer */}
                    {rawOpen && (
                      <div className="ledger-raw-drawer animate-fade-in">
                        <div className="raw-drawer-header font-mono">
                          <span className="raw-label">ORIGINAL UNTOUCHED EVIDENCE PAYLOAD:</span>
                          <span className="raw-file-tag">Source: {ev.evidenceFile}</span>
                        </div>
                        <pre className="ledger-raw-snippet font-mono">{ev.raw || ev.message}</pre>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
