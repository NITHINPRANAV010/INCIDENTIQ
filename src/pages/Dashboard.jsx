import { useNavigate } from 'react-router-dom'
import {
  Plus,
  ChevronRight,
  AlertTriangle,
  FileText,
  Shield,
  Crosshair,
  Terminal,
  ArrowUpRight,
  Network,
} from 'lucide-react'
import { useInvestigation } from '../context/InvestigationContext'
import './Dashboard.css'

function getSeverityClass(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'info'
  }
}

function getStatusLabel(status) {
  switch (status) {
    case 'complete':  return 'Completed'
    case 'analyzing': return 'Analyzing'
    case 'error':     return 'Error'
    default:          return 'Investigating'
  }
}

function formatRelativeTime(isoStr) {
  if (!isoStr) return '—'
  const diff = Date.now() - new Date(isoStr).getTime()
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days  = Math.floor(diff / 86400000)
  if (mins  < 1)  return 'Just now'
  if (mins  < 60) return `${mins}m ago`
  if (hours < 24) return `${hours}h ago`
  return `${days}d ago`
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { investigations, reports, stats, setActiveInvestigationId } = useInvestigation()

  const allFindings = investigations
    .filter(i => i.analysisResult?.findings?.length > 0)
    .flatMap(i => (i.analysisResult.findings || []).map(f => ({ ...f, incidentId: i.id, incidentName: i.name })))

  const recentFindings = allFindings.slice(0, 8)

  // 1. Threat Vector / MITRE ATT&CK distribution
  const vectorDefinitions = [
    {
      id: 'T1110',
      name: 'Initial Access & Auth Abuse',
      regex: /auth|login|brute|credential|password/i,
      color: 'var(--critical)',
    },
    {
      id: 'T1548',
      name: 'Privilege Escalation',
      regex: /privilege|sudo|root|escalat|admin/i,
      color: 'var(--critical)',
    },
    {
      id: 'T1071',
      name: 'Command & Control (C2)',
      regex: /c2|network|outbound|reverse|beacon|4444|socket/i,
      color: 'var(--high)',
    },
    {
      id: 'T1070',
      name: 'Defense Evasion & Persistence',
      regex: /evasion|clear|tamper|hidden|persistence|scheduled|bash|process/i,
      color: 'var(--medium)',
    },
  ]

  const vectorStats = vectorDefinitions.map(v => {
    const matches = allFindings.filter(f => v.regex.test((f.title || '') + ' ' + (f.shortExplanation || ''))).length
    return { ...v, count: matches }
  })
  const totalVectorMatches = vectorStats.reduce((acc, v) => acc + v.count, 0) || 1
  const dominantVector = [...vectorStats].sort((a, b) => b.count - a.count)[0]

  // 2. Extracted Key Indicators (IOCs) from events and verdicts
  const allIndicators = []
  const seenIndicators = new Set()

  for (const inv of investigations) {
    // Extract technical IOCs from events
    for (const ev of (inv.events || [])) {
      if (ev.sourceIp && !seenIndicators.has(ev.sourceIp) && !ev.sourceIp.startsWith('127.') && !ev.sourceIp.startsWith('0.')) {
        seenIndicators.add(ev.sourceIp)
        allIndicators.push({ text: ev.sourceIp, type: 'IP', incidentId: inv.id })
      }
      if (ev.destinationIp && !seenIndicators.has(ev.destinationIp) && !ev.destinationIp.startsWith('127.')) {
        seenIndicators.add(ev.destinationIp)
        allIndicators.push({ text: ev.destinationIp, type: 'IP', incidentId: inv.id })
      }
      if (ev.port && (ev.port === 4444 || ev.port === 1337 || ev.port === 9001) && !seenIndicators.has(`Port ${ev.port}`)) {
        seenIndicators.add(`Port ${ev.port}`)
        allIndicators.push({ text: `Port ${ev.port} (C2 Socket)`, type: 'C2', incidentId: inv.id })
      }
      if (ev.user && !['unknown', 'system', 'daemon'].includes(ev.user.toLowerCase()) && !seenIndicators.has(`user:${ev.user}`)) {
        seenIndicators.add(`user:${ev.user}`)
        allIndicators.push({ text: `Account: ${ev.user}`, type: 'AUTH', incidentId: inv.id })
      }
    }

    // Extract from verdict keyIndicators
    const indicators = inv.analysisResult?.verdict?.keyIndicators || []
    for (const ind of indicators) {
      const clean = (typeof ind === 'string' ? ind : ind.title || ind.text || '').trim()
      if (clean && !seenIndicators.has(clean.toLowerCase())) {
        seenIndicators.add(clean.toLowerCase())
        let type = 'IOC'
        if (/(\d{1,3}\.){3}\d{1,3}/.test(clean)) type = 'IP'
        else if (/port|4444|tcp|socket|dns/i.test(clean)) type = 'NET'
        else if (/sudo|root|auth|user|login|account/i.test(clean)) type = 'AUTH'
        else if (/c2|shell|beacon|reverse/i.test(clean)) type = 'C2'
        else if (/mimikatz|cron|exec|\.exe|\.sh|process/i.test(clean)) type = 'PROC'
        allIndicators.push({ text: clean, type, incidentId: inv.id })
      }
    }
  }

  // Fallback indicator examples from actual findings if needed
  if (allIndicators.length === 0 && allFindings.length > 0) {
    allFindings.slice(0, 5).forEach((f) => {
      allIndicators.push({
        text: f.title,
        type: f.title.toLowerCase().includes('c2') ? 'C2' : f.title.toLowerCase().includes('privilege') ? 'AUTH' : 'IOC',
        incidentId: f.incidentId,
      })
    })
  }

  // 3. Priority Containment Directives
  const allDirectives = investigations.flatMap(inv =>
    (inv.recommendations || []).map(rec => ({
      ...rec,
      incidentId: inv.id,
      incidentName: inv.name,
    }))
  ).slice(0, 6)

  // Fallback directives if investigations don't have explicit recommendations yet
  const fallbackDirectives = allFindings
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 4)
    .map((f, i) => ({
      id: `DIR-00${i + 1}`,
      priority: f.severity === 'CRITICAL' ? 'IMMEDIATE' : 'SHORT-TERM',
      action: f.title.toLowerCase().includes('c2')
        ? 'Isolate Host and Sever External C2 Socket'
        : f.title.toLowerCase().includes('privilege')
          ? 'Revoke Elevated Permissions and Audit Sudoers'
          : 'Enforce Credential Reset & Session Invalidation',
      incidentId: f.incidentId,
    }))

  const displayDirectives = allDirectives.length > 0 ? allDirectives : fallbackDirectives

  // 4. Raw events processed
  const totalEventsCount = investigations.reduce((sum, i) => sum + (i.events?.length || 0), 0)

  const handleOpen = (inv) => {
    setActiveInvestigationId(inv.id)
    navigate(`/investigate/${inv.id}`)
  }

  return (
    <div className="dashboard-page">
      {/* Header */}
      <div className="dash-header">
        <div>
          <h1 className="dash-title">Security Operations Console</h1>
          <p className="dash-subtitle">Real-time incident triage, evidence correlation, and forensic intelligence overview.</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => navigate('/investigate')}
          id="new-investigation-btn"
        >
          <Plus size={13} />
          New Investigation
        </button>
      </div>

      {/* Metrics Strip */}
      <div className="metrics-strip">
        <div className="metric-block" id="metric-active-incidents">
          <span className="metric-block-label">Active Incidents</span>
          <span className="metric-block-value font-mono">{stats.active || investigations.length || 0}</span>
        </div>
        <div className="metric-block" id="metric-critical">
          <span className="metric-block-label">Critical Findings</span>
          <span className={`metric-block-value font-mono${stats.critical > 0 ? ' val-critical' : ''}`}>
            {stats.critical || 0}
          </span>
        </div>
        <div className="metric-block" id="metric-evidence-items">
          <span className="metric-block-label">Evidence Artifacts</span>
          <span className="metric-block-value font-mono">{stats.evidenceItems || 0}</span>
        </div>
        <div className="metric-block" id="metric-investigations">
          <span className="metric-block-label">Incident Reports</span>
          <span className="metric-block-value font-mono">{reports.length}</span>
        </div>
      </div>

      {/* Two-Column Main Grid */}
      <div className="dash-grid">
        {/* Active Investigations Table */}
        <div className="dash-panel inv-panel">
          <div className="dash-panel-header">
            <span className="dash-panel-title">Active Investigations</span>
            <span className="dash-panel-count">{investigations.length}</span>
          </div>

          <div className="table-wrapper">
            {investigations.length === 0 ? (
              <div className="empty-state">
                <AlertTriangle size={22} className="empty-state-icon" />
                <p>No active investigations.</p>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => navigate('/investigate')}
                >
                  <Plus size={12} /> New Investigation
                </button>
              </div>
            ) : (
              <table className="table inv-table">
                <thead>
                  <tr>
                    <th style={{ width: '104px' }}>ID</th>
                    <th>Incident</th>
                    <th style={{ width: '92px' }}>Severity</th>
                    <th style={{ width: '115px' }}>Status</th>
                    <th style={{ width: '85px' }}>Updated</th>
                    <th style={{ width: '64px', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {investigations.map(inv => {
                    const severity = inv.analysisResult?.verdict?.severity
                    const sevClass = getSeverityClass(severity)
                    const incidentType = inv.analysisResult?.verdict?.incidentType
                    return (
                      <tr key={inv.id} id={`inv-row-${inv.id}`}>
                        <td>
                          <span className="inv-id-tag">{inv.id}</span>
                        </td>
                        <td>
                          <div className="inv-name-col">
                            <span className="inv-name-text">{inv.name}</span>
                            {incidentType && (
                              <span className="inv-type-text">{incidentType}</span>
                            )}
                          </div>
                        </td>
                        <td>
                          {severity ? (
                            <span className={`badge badge-${sevClass}`}>{severity}</span>
                          ) : (
                            <span className="text-muted font-mono" style={{ fontSize: 11 }}>—</span>
                          )}
                        </td>
                        <td>
                          <span className="status-tag">
                            <span
                              className={`status-dot ${
                                inv.status === 'complete'  ? 'complete'  :
                                inv.status === 'analyzing' ? 'analyzing' :
                                inv.status === 'error'     ? 'error'     : 'ready'
                              }`}
                            />
                            {getStatusLabel(inv.status)}
                          </span>
                        </td>
                        <td>
                          <span className="time-text">{formatRelativeTime(inv.updatedAt)}</span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn-ghost btn-sm open-link"
                            onClick={() => handleOpen(inv)}
                            id={`open-inv-${inv.id}`}
                          >
                            Open <ChevronRight size={11} />
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Recent Findings Panel */}
        <div className="dash-panel findings-panel">
          <div className="dash-panel-header">
            <span className="dash-panel-title">Correlated Findings</span>
            <span className="dash-panel-count">{recentFindings.length}</span>
          </div>
          <div className="recent-findings-list">
            {recentFindings.length === 0 ? (
              <div className="empty-state-compact">
                <FileText size={18} style={{ marginBottom: 6, color: 'var(--text-disabled)' }} />
                <p>No findings yet. Run an investigation to see correlated results here.</p>
              </div>
            ) : (
              recentFindings.map((f, idx) => {
                const sevClass = getSeverityClass(f.severity)
                return (
                  <div key={idx} className="recent-finding-row">
                    <div className="finding-lead">
                      <span className={`status-dot dot-${sevClass} finding-dot`} />
                      <div className="finding-info">
                        <span className="finding-title-text" title={f.title}>{f.title}</span>
                        <span className="finding-incident-ref">{f.incidentId}</span>
                      </div>
                    </div>
                    <span className={`badge badge-${sevClass}`}>{f.severity}</span>
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>

      {/* Secondary Intelligence Grid (3 columns) */}
      <div className="dash-secondary-grid">
        {/* Panel 1: Threat Vectors & ATT&CK Alignment */}
        <div className="dash-panel vector-panel">
          <div className="dash-panel-header">
            <span className="dash-panel-title">
              <Crosshair size={12} className="panel-title-icon" />
              Threat Vectors & ATT&CK
            </span>
            <span className="dash-panel-count">{allFindings.length} Detected</span>
          </div>
          <div className="vector-content">
            {vectorStats.map((v) => {
              const pct = Math.min(100, Math.round((v.count / totalVectorMatches) * 100))
              return (
                <div key={v.id} className="vector-row">
                  <div className="vector-meta">
                    <div className="vector-title-group">
                      <span className="vector-id">{v.id}</span>
                      <span className="vector-name">{v.name}</span>
                    </div>
                    <span className="vector-count font-mono">{v.count}</span>
                  </div>
                  <div className="vector-bar-track">
                    <div
                      className="vector-bar-fill"
                      style={{
                        width: `${Math.max(v.count > 0 ? 12 : 3, pct)}%`,
                        background: v.color,
                      }}
                    />
                  </div>
                </div>
              )
            })}
            <div className="vector-summary-footer">
              <span className="vector-footer-label">Primary Attack Vector:</span>
              <span className="vector-footer-val">{dominantVector?.name || 'Awaiting telemetry'}</span>
            </div>
          </div>
        </div>

        {/* Panel 2: Indicators of Compromise (IOC Vault) */}
        <div className="dash-panel ioc-panel">
          <div className="dash-panel-header">
            <span className="dash-panel-title">
              <Terminal size={12} className="panel-title-icon" />
              Key Indicators (IOCs)
            </span>
            <span className="dash-panel-count">{allIndicators.length} Unique</span>
          </div>
          <div className="ioc-content">
            {allIndicators.length === 0 ? (
              <div className="empty-state-compact">
                <Network size={18} style={{ color: 'var(--text-disabled)' }} />
                <p>No external IOCs flagged yet in active investigation scope.</p>
              </div>
            ) : (
              <div className="ioc-list">
                {allIndicators.slice(0, 8).map((ioc, idx) => (
                  <div key={idx} className="ioc-pill">
                    <span className={`ioc-badge ioc-${ioc.type.toLowerCase()}`}>{ioc.type}</span>
                    <span className="ioc-text" title={ioc.text}>{ioc.text}</span>
                    <button
                      className="ioc-ref-btn"
                      onClick={() => {
                        setActiveInvestigationId(ioc.incidentId)
                        navigate(`/investigate/${ioc.incidentId}`)
                      }}
                      title={`Jump to ${ioc.incidentId}`}
                    >
                      <span>{ioc.incidentId}</span>
                      <ArrowUpRight size={10} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Panel 3: Containment Directives */}
        <div className="dash-panel directives-panel">
          <div className="dash-panel-header">
            <span className="dash-panel-title">
              <Shield size={12} className="panel-title-icon" />
              Containment Directives
            </span>
            <span className="dash-panel-count">{displayDirectives.length} Actionable</span>
          </div>
          <div className="directives-content">
            {displayDirectives.length === 0 ? (
              <div className="empty-state-compact">
                <Shield size={18} style={{ color: 'var(--text-disabled)' }} />
                <p>No critical response directives currently queued.</p>
              </div>
            ) : (
              <div className="directives-list">
                {displayDirectives.map((d, idx) => (
                  <div key={idx} className="directive-item">
                    <div className="directive-header">
                      <span className={`badge ${d.priority === 'IMMEDIATE' ? 'badge-critical' : 'badge-high'}`}>
                        {d.priority || 'PRIORITY'}
                      </span>
                      <button
                        className="directive-ref"
                        onClick={() => {
                          setActiveInvestigationId(d.incidentId)
                          navigate(`/investigate/${d.incidentId}`)
                        }}
                      >
                        {d.incidentId} <ChevronRight size={10} />
                      </button>
                    </div>
                    <div className="directive-action-text">{d.action}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Enterprise SOC Telemetry Ribbon */}
      <div className="dash-telemetry-ribbon">
        <div className="ribbon-item">
          <span className="ribbon-dot dot-live" />
          <span className="ribbon-label">Ingestion Engine:</span>
          <span className="ribbon-val">ONLINE (.log, .json, .csv, .txt)</span>
        </div>
        <div className="ribbon-divider" />
        <div className="ribbon-item">
          <span className="ribbon-dot dot-ai" />
          <span className="ribbon-label">AI Reasoning Core:</span>
          <span className="ribbon-val">Gemini 2.5 Multi-Stage</span>
        </div>
        <div className="ribbon-divider" />
        <div className="ribbon-item">
          <span className="ribbon-dot dot-live" />
          <span className="ribbon-label">Correlation Stream:</span>
          <span className="ribbon-val">{totalEventsCount} Events Normalized</span>
        </div>
        <div className="ribbon-divider" />
        <div className="ribbon-item">
          <span className="ribbon-dot dot-matrix" />
          <span className="ribbon-label">Threat Matrix:</span>
          <span className="ribbon-val">MITRE ATT&CK v14.1</span>
        </div>
        <div className="ribbon-divider" />
        <div className="ribbon-item">
          <span className="ribbon-dot dot-live" />
          <span className="ribbon-label">Readiness Status:</span>
          <span className="ribbon-val font-mono">NOMINAL / SOC-T2</span>
        </div>
      </div>
    </div>
  )
}
