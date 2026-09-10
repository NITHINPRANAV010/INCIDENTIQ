import { useState } from 'react'
import { Download, Eye, FileText, X } from 'lucide-react'
import { useInvestigation } from '../context/InvestigationContext'
import { formatReportAsText } from '../services/reportBuilder'
import './Reports.css'

function getSeverityClass(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'info'
  }
}

function formatDate(isoStr) {
  if (!isoStr) return '—'
  const d = new Date(isoStr)
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}

function ReportModal({ report, onClose }) {
  if (!report) return null

  const handleDownload = () => {
    const text = formatReportAsText(report)
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.incidentId}_incident_report.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const sevClass = getSeverityClass(report.severity)

  return (
    <div className="modal-overlay animate-fade-in" onClick={onClose} role="dialog" aria-modal="true" aria-label="Report viewer">
      <div className="modal-container" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <div className="modal-incident-id font-mono">{report.incidentId}</div>
            <h2 className="modal-title">{report.incidentName}</h2>
          </div>
          <div className="modal-header-right">
            <button className="btn btn-secondary btn-sm" onClick={handleDownload} id="modal-download-btn">
              <Download size={12} /> Download
            </button>
            <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close report">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="report-meta-strip font-mono">
          <span className={`badge badge-${sevClass}`}>{report.severity}</span>
          <span>{report.classification || 'CONFIDENTIAL'}</span>
          <span>&middot;</span>
          <span>{formatDate(report.generatedAt || report.savedAt)}</span>
        </div>

        <div className="modal-body font-mono">
          <pre className="report-content-pre">
            {formatReportAsText(report)}
          </pre>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Reports() {
  const { reports } = useInvestigation()
  const [viewReport, setViewReport] = useState(null)

  return (
    <div className="reports-page">
      <div className="dash-header">
        <div>
          <h1 className="dash-title">INCIDENT REPORTS</h1>
          <p className="dash-subtitle">Archive of formal incident response reports.</p>
        </div>
      </div>

      <div className="card dash-panel">
        <div className="table-wrapper">
          {reports.length === 0 ? (
            <div className="empty-state">
              <FileText size={28} className="empty-state-icon" />
              <p>No incident reports generated yet.</p>
              <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Complete an investigation and generate a report to view here.
              </p>
            </div>
          ) : (
            <table className="table" id="reports-table">
              <thead>
                <tr>
                  <th style={{ width: '120px' }}>INCIDENT</th>
                  <th>TYPE</th>
                  <th style={{ width: '110px' }}>SEVERITY</th>
                  <th style={{ width: '130px' }}>DATE</th>
                  <th style={{ width: '110px' }}>STATUS</th>
                  <th style={{ width: '80px', textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report, idx) => {
                  const sevClass = getSeverityClass(report.severity)
                  const incidentType = report.metadata?.incidentType || report.classification || 'Account Compromise'

                  return (
                    <tr key={report.reportId || idx} id={`report-row-${report.incidentId}`}>
                      <td>
                        <span className="inv-id-tag font-mono">{report.incidentId}</span>
                      </td>
                      <td>
                        <span className="inv-name-text">{incidentType}</span>
                      </td>
                      <td>
                        <span className={`badge badge-${sevClass}`}>{report.severity || '—'}</span>
                      </td>
                      <td>
                        <span className="time-text font-mono">
                          {formatDate(report.savedAt || report.generatedAt)}
                        </span>
                      </td>
                      <td>
                        <span className="status-tag">
                          <span className="status-dot complete" />
                          Complete
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-ghost btn-sm open-link font-mono"
                          onClick={() => setViewReport(report)}
                          id={`view-report-${report.incidentId}`}
                        >
                          <Eye size={12} /> VIEW
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

      {viewReport && (
        <ReportModal report={viewReport} onClose={() => setViewReport(null)} />
      )}
    </div>
  )
}
