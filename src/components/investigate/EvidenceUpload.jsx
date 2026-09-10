import { useState, useRef, useCallback } from 'react'
import { Upload, X, FileText, File, AlertCircle, FlaskConical, CheckCircle2, AlertTriangle } from 'lucide-react'
import { SAMPLE_INCIDENT } from '../../data/sampleIncident'
import { validateFileMetadata, formatFileSize, SUPPORTED_EXTENSIONS } from '../../services/evidenceParser'
import './EvidenceUpload.css'

function getFileIcon(name) {
  const ext = (name || '').split('.').pop().toLowerCase()
  if (ext === 'json') return <File size={14} />
  return <FileText size={14} />
}

export default function EvidenceUpload({
  incidentName,
  setIncidentName,
  incidentDesc,
  setIncidentDesc,
  files,
  setFiles,
  onAnalyze,
  isLoading,
}) {
  const [dragging, setDragging] = useState(false)
  const [sampleLoaded, setSampleLoaded] = useState(false)
  const [validationAlert, setValidationAlert] = useState(null)
  const fileInputRef = useRef(null)

  const processIncomingFiles = useCallback((incomingFiles) => {
    setValidationAlert(null)
    const newItems = []
    let rejectedCount = 0
    let lastError = null

    for (const f of incomingFiles) {
      const metaCheck = validateFileMetadata(f)
      const ext = (f.name.split('.').pop() || '').toLowerCase()
      const sizeStr = formatFileSize(f.size)

      if (!metaCheck.valid) {
        rejectedCount++
        lastError = metaCheck.error
        newItems.push({
          name: f.name,
          type: ext || 'unknown',
          size: sizeStr,
          status: 'error',
          error: metaCheck.error,
          rawFile: f,
        })
      } else {
        newItems.push({
          name: f.name,
          type: ext,
          size: sizeStr,
          status: 'ready',
          error: null,
          rawFile: f,
        })
      }
    }

    if (rejectedCount > 0) {
      setValidationAlert(lastError || `${rejectedCount} file(s) failed validation.`)
    }

    setFiles(prev => {
      const existing = new Set(prev.map(p => p.name))
      const deduped = newItems.filter(item => !existing.has(item.name))
      return [...prev, ...deduped]
    })
    setSampleLoaded(false)
  }, [setFiles])

  const onDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    if (e.dataTransfer?.files?.length) {
      processIncomingFiles(Array.from(e.dataTransfer.files))
    }
  }, [processIncomingFiles])

  const onDragOver = (e) => { e.preventDefault(); setDragging(true) }
  const onDragLeave = () => setDragging(false)

  const onFileSelect = (e) => {
    if (e.target.files?.length) {
      processIncomingFiles(Array.from(e.target.files))
    }
    e.target.value = ''
  }

  const removeFile = (name) => {
    setFiles(prev => prev.filter(f => f.name !== name))
  }

  const loadSample = () => {
    setSampleLoaded(true)
    setValidationAlert(null)
    if (!incidentName) setIncidentName(SAMPLE_INCIDENT.name)
    if (!incidentDesc) setIncidentDesc(SAMPLE_INCIDENT.description)

    const formattedSample = SAMPLE_INCIDENT.files.map(f => ({
      name: f.name,
      type: f.type,
      size: f.size,
      status: 'ready',
      error: null,
      content: f.content,
      rawFile: f,
    }))
    setFiles(formattedSample)
  }

  const validFiles = files.filter(f => f.status !== 'error')
  const errorFiles = files.filter(f => f.status === 'error')
  const canAnalyze = validFiles.length > 0 && incidentName.trim().length > 0

  return (
    <div className="evidence-panel animate-fade-in">
      {/* Panel Header */}
      <div className="evidence-panel-header">
        <h3 className="evidence-header-title">EVIDENCE</h3>
        <p className="evidence-header-sub">Security artifacts used for this investigation</p>
      </div>

      <div className="evidence-form">
        {/* Incident Name & Description Inputs */}
        <div className="form-group">
          <label className="form-label" htmlFor="incident-name">Incident Name</label>
          <input
            id="incident-name"
            type="text"
            className="form-input"
            placeholder="e.g. Suspicious Server Activity"
            value={incidentName}
            onChange={e => setIncidentName(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="incident-desc">
            Description <span className="optional">(optional context)</span>
          </label>
          <textarea
            id="incident-desc"
            className="form-input form-textarea"
            placeholder="Brief scope, target system, or initial telemetry notes..."
            value={incidentDesc}
            onChange={e => setIncidentDesc(e.target.value)}
          />
        </div>

        {/* Compact Drop Area */}
        <div className="form-group">
          <div
            className={`drop-zone-compact ${dragging ? 'dragging' : ''}`}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            aria-label="Upload evidence files"
            id="evidence-drop-zone"
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept={SUPPORTED_EXTENSIONS.map(ext => `.${ext}`).join(',')}
              onChange={onFileSelect}
              style={{ display: 'none' }}
            />
            <Upload size={18} className="drop-icon" />
            <div className="drop-text-group">
              <span className="drop-primary-text">DROP FILES OR BROWSE</span>
              <span className="drop-formats-text font-mono">.log .txt .json .csv</span>
            </div>
          </div>
        </div>

        {/* Validation Alert */}
        {validationAlert && (
          <div className="upload-alert-banner animate-fade-in" id="upload-validation-error">
            <AlertCircle size={14} />
            <span>{validationAlert}</span>
            <button className="banner-close-btn" onClick={() => setValidationAlert(null)}>
              <X size={12} />
            </button>
          </div>
        )}

        {/* Mixed Files Warning */}
        {files.length > 0 && errorFiles.length > 0 && validFiles.length > 0 && (
          <div className="mixed-files-summary animate-fade-in">
            <AlertTriangle size={13} className="text-warning" />
            <span>
              {validFiles.length} file(s) ready. {errorFiles.length} file(s) could not be parsed.
            </span>
          </div>
        )}

        {/* Uploaded Evidence Section */}
        {files.length > 0 && (
          <div className="uploaded-evidence-section">
            <div className="uploaded-evidence-header">
              <span className="section-label">UPLOADED EVIDENCE</span>
              <span className="files-count font-mono">{validFiles.length} valid</span>
            </div>

            <div className="file-list">
              {files.map(file => {
                const isError = file.status === 'error'
                return (
                  <div
                    key={file.name}
                    className={`file-item ${isError ? 'file-item-error' : ''}`}
                    id={`file-${file.name.replace(/\./g, '-')}`}
                  >
                    <div className={`file-icon ${isError ? 'icon-error' : ''}`}>
                      {getFileIcon(file.name)}
                    </div>
                    <div className="file-info">
                      <span className="file-name">{file.name}</span>
                      <span className="file-meta font-mono">
                        {(file.type || 'unknown').toUpperCase()} &middot; {file.size}
                      </span>
                      {isError && (
                        <span className="file-error-detail font-mono">
                          {file.error}
                        </span>
                      )}
                    </div>
                    <div className="file-status">
                      {isError ? (
                        <span className="badge badge-critical">Error</span>
                      ) : (
                        <span className="badge badge-accent">
                          <CheckCircle2 size={10} style={{ marginRight: 3, verticalAlign: 'middle' }} />
                          Ready
                        </span>
                      )}
                    </div>
                    <button
                      className="btn btn-icon btn-ghost file-remove"
                      onClick={(e) => { e.stopPropagation(); removeFile(file.name) }}
                      aria-label={`Remove ${file.name}`}
                    >
                      <X size={13} />
                    </button>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Actions row: Load Sample & Primary CTA */}
        <div className="evidence-action-row">
          <button
            className="btn btn-secondary sample-btn"
            onClick={loadSample}
            id="load-sample-btn"
            type="button"
          >
            <FlaskConical size={13} />
            LOAD SAMPLE INCIDENT
            {sampleLoaded && <span className="sample-loaded-dot" title="Sample loaded" />}
          </button>

          <button
            className="btn btn-primary btn-lg analyze-btn"
            onClick={onAnalyze}
            disabled={!canAnalyze || isLoading}
            id="analyze-btn"
          >
            {isLoading ? <><span className="spinner" />Analyzing...</> : 'ANALYZE INCIDENT →'}
          </button>
        </div>

        {!canAnalyze && (
          <div className="form-hint">
            <AlertCircle size={12} />
            <span>
              {!incidentName.trim()
                ? 'Provide an incident name'
                : files.length === 0
                  ? 'Upload evidence or load sample incident'
                  : 'Please upload at least one valid evidence file'}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
