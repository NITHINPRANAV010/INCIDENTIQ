import { useState } from 'react'
import { Download, Eye, X, CheckCircle2 } from 'lucide-react'
import { generateReportContent } from '../../services/gemini'
import { buildReport, formatReportAsText } from '../../services/reportBuilder'
import './GenerateReport.css'

export default function GenerateReport({ investigation, onReportGenerated }) {
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const done = !!investigation?.report

  const handleGenerate = async () => {
    setGenerating(true)
    setError(null)
    try {
      const reportContent = await generateReportContent(investigation)
      const report = buildReport(investigation, reportContent)
      onReportGenerated?.(report)
    } catch (err) {
      setError(err.message)
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = () => {
    if (!investigation?.report) return
    const text = formatReportAsText(investigation.report)
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${investigation.id}_incident_report.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const report = investigation?.report

  return (
    <div className="generate-report-section" id="generate-report-section">
      <div className="gen-report-panel">
        {!done ? (
          <div className="gen-trigger-state">
            <div className="gen-info-col">
              <h3 className="gen-report-title">INCIDENT REPORT</h3>
              <p className="gen-report-desc">
                Compile formal incident response report with executive summary, confirmed findings, IOCs, and response actions.
              </p>
            </div>

            <button
              className="btn btn-primary btn-lg gen-report-primary-btn"
              onClick={handleGenerate}
              disabled={generating}
              id="generate-report-btn"
            >
              {generating ? (
                <><span className="spinner" />Compiling Report...</>
              ) : (
                'GENERATE INCIDENT REPORT →'
              )}
            </button>
          </div>
        ) : (
          <div className="gen-completed-state animate-fade-in">
            <div className="report-ready-info">
              <div className="report-ready-header">
                <span className="report-ready-label font-mono">REPORT GENERATED</span>
              </div>
              <div className="report-ready-check">
                <CheckCircle2 size={15} className="text-success" />
                <span className="report-ready-sub">Incident report ready for technical and executive review</span>
              </div>
            </div>

            <div className="report-ready-buttons">
              <button
                className="btn btn-secondary"
                onClick={() => setShowModal(true)}
                id="view-report-btn"
              >
                <Eye size={13} />
                VIEW REPORT
              </button>
              <button
                className="btn btn-primary"
                onClick={handleDownload}
                id="download-report-btn"
              >
                <Download size={13} />
                DOWNLOAD REPORT
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="gen-report-error animate-fade-in">{error}</div>
        )}
      </div>

      {/* Report Modal */}
      {showModal && report && (
        <div className="modal-overlay animate-fade-in" onClick={() => setShowModal(false)}>
          <div className="modal-container" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h2 className="modal-title font-mono">{report.incidentId} &middot; Formal Incident Report</h2>
                <p className="modal-sub font-mono">{report.metadata?.classification || 'CONFIDENTIAL'} &middot; {report.metadata?.generatedAt}</p>
              </div>
              <button className="btn btn-icon btn-ghost" onClick={() => setShowModal(false)}>
                <X size={16} />
              </button>
            </div>

            <div className="modal-body font-mono">
              <pre className="report-content-pre">
                {formatReportAsText(report)}
              </pre>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary btn-sm" onClick={() => setShowModal(false)}>
                Close
              </button>
              <button className="btn btn-primary btn-sm" onClick={handleDownload}>
                <Download size={12} /> Download .txt
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
