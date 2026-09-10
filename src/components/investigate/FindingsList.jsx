import { useState } from 'react'
import { ChevronDown, ChevronUp, FileText, ArrowUpRight, AlertTriangle, ShieldCheck, Cpu } from 'lucide-react'
import './FindingsList.css'

function getSeverityClass(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'info'
  }
}

function FindingCard({ finding, index, eventLookup, onEventClick }) {
  const [expanded, setExpanded] = useState(false)
  const sevClass = getSeverityClass(finding.severity)
  const conf = Math.round(finding.confidence || 0)

  // 11. Validate every supportingEventId before displaying it.
  // If an ID does not exist in the investigation's actual event collection, reject that reference.
  const rawSupportingIds = Array.isArray(finding.supportingEventIds)
    ? finding.supportingEventIds
    : (finding.supportingEvents || []).map(se => (typeof se === 'string' ? se : se.eventId)).filter(Boolean)

  const validatedSupportingEvents = []
  const validatedSupportingIds = []

  for (const id of rawSupportingIds) {
    const realEv = eventLookup?.get(id)
    if (realEv) {
      validatedSupportingIds.push(id)
      validatedSupportingEvents.push(realEv)
    }
    // Rejected reference if realEv does not exist
  }

  // Determine if evidence is insufficient
  const isInsufficient = finding.isInsufficientEvidence || validatedSupportingEvents.length === 0

  // 4. Extract unique source files from validated supporting events
  const sourceFiles = [
    ...new Set(validatedSupportingEvents.map(e => e.evidenceFile || e.source).filter(Boolean))
  ]

  return (
    <div
      className={`finding-row-card animate-fade-in finding-${sevClass}`}
      style={{ animationDelay: `${index * 40}ms` }}
      id={`finding-${finding.id}`}
    >
      {/* ── Top Header Row ── */}
      <div className="finding-top-row">
        <div className="finding-sev-group">
          <span className={`status-dot dot-${sevClass}`} />
          <span className={`badge badge-${sevClass}`}>{finding.severity}</span>
          <span className="finding-conf font-mono">{conf}% confidence</span>

          {isInsufficient ? (
            <span className="badge badge-warning" title="No verified telemetry backing this hypothesis">
              <AlertTriangle size={9} style={{ marginRight: 3 }} />
              Insufficient Evidence
            </span>
          ) : finding.isInferred ? (
            <span className="badge badge-info" title="AI-correlated conclusion from confirmed events">
              <Cpu size={9} style={{ marginRight: 3 }} />
              AI Inference
            </span>
          ) : (
            <span className="badge badge-accent" title="Directly confirmed by logged telemetry">
              <ShieldCheck size={9} style={{ marginRight: 3 }} />
              Confirmed Evidence
            </span>
          )}
        </div>

        {/* 5. Expandable "Why this finding?" button */}
        <button
          className={`btn btn-ghost btn-sm finding-why-btn font-mono ${expanded ? 'active' : ''}`}
          onClick={() => setExpanded(e => !e)}
          aria-expanded={expanded}
          aria-label={expanded ? 'Collapse finding detail' : 'Expand finding detail'}
        >
          <span>Why this finding?</span>
          {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      {/* ── Title & Explanation ── */}
      <div className="finding-body">
        <h4 className="finding-title">{finding.title}</h4>
        <p className="finding-explanation">{finding.shortExplanation}</p>
      </div>

      {/* ── Supporting Event IDs & Source Files Footer ── */}
      <div className="finding-evidence-footer">
        {validatedSupportingIds.length > 0 ? (
          <div className="evidence-trace-row">
            <span className="evidence-ids-label font-mono">Supporting Evidence:</span>
            <div className="evidence-pill-list">
              {validatedSupportingIds.map(eventId => {
                const realEv = eventLookup?.get(eventId)
                return (
                  <button
                    key={eventId}
                    type="button"
                    className="event-pill-btn font-mono"
                    onClick={() => onEventClick?.(eventId)}
                    title={`Click to view event ${eventId} in evidence ledger (${realEv?.evidenceFile || 'telemetry'})`}
                  >
                    <span className="event-id">{eventId}</span>
                    {realEv?.source && (
                      <span className="event-source-tag">{realEv.source}</span>
                    )}
                    <ArrowUpRight size={9} className="pill-arrow-icon" />
                  </button>
                )
              })}
            </div>
          </div>
        ) : (
          <div className="evidence-trace-row">
            <span className="evidence-ids-label font-mono text-warning">Notice:</span>
            <span className="no-evidence-note font-mono">
              Insufficient telemetry to confirm event-level traceability.
            </span>
          </div>
        )}

        {sourceFiles.length > 0 && (
          <div className="finding-sources-tag-group font-mono">
            <span className="sources-label">Source File(s):</span>
            {sourceFiles.map(file => (
              <span key={file} className="source-file-chip">
                <FileText size={9} style={{ marginRight: 3 }} />
                {file}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* ── 6. Expanded "Why this finding?" Section with TWO clearly separated sections ── */}
      {expanded && (
        <div className="finding-expanded-audit animate-fade-in">
          <div className="audit-header font-mono">
            <span>EVIDENCE TRACEABILITY AUDIT TRAIL</span>
            <span className="audit-sub">Finding {finding.id} &middot; {validatedSupportingEvents.length} Event(s) Correlated</span>
          </div>

          {/* 6. Section 1: CONFIRMED EVIDENCE */}
          <div className="audit-section audit-confirmed-section">
            <div className="audit-section-label confirmed">
              <span className="audit-dot confirmed-dot" />
              CONFIRMED EVIDENCE
              <span className="section-subtitle font-mono">Direct verified telemetry parsed from original evidence files</span>
            </div>

            {validatedSupportingEvents.length > 0 ? (
              <div className="audit-event-list">
                {validatedSupportingEvents.map(realEv => {
                  const sourceFile = realEv.evidenceFile || realEv.source || 'Evidence file'
                  const rawLog = realEv.raw || realEv.message

                  return (
                    <div key={realEv.eventId} className="audit-event-card" id={`audit-card-${realEv.eventId}`}>
                      {/* Event Card Header */}
                      <div className="audit-event-top">
                        <div className="audit-id-badge-group">
                          <button
                            type="button"
                            className="event-id-btn font-mono"
                            onClick={() => onEventClick?.(realEv.eventId)}
                            title="Jump to this event in the Evidence Ledger"
                          >
                            <span>{realEv.eventId}</span>
                            <ArrowUpRight size={10} />
                          </button>
                          <span className="audit-time-tag font-mono">
                            {realEv.timestamp || 'No timestamp'}
                          </span>
                        </div>

                        <div className="audit-source-info font-mono">
                          <span className="audit-type-pill">{realEv.eventType || 'event'}</span>
                          <span className="audit-source-file" title={`Origin: ${sourceFile}`}>
                            <FileText size={10} style={{ marginRight: 3 }} />
                            {sourceFile}
                          </span>
                        </div>
                      </div>

                      {/* Event Structured Metadata (User, IPs, Process, Action) */}
                      <div className="audit-metadata-grid font-mono">
                        {realEv.username && (
                          <div className="meta-pair">
                            <span className="meta-key">User:</span>
                            <span className="meta-val user-val">{realEv.username}</span>
                          </div>
                        )}
                        {realEv.sourceIp && (
                          <div className="meta-pair">
                            <span className="meta-key">Source IP:</span>
                            <span className="meta-val ip-val">
                              {realEv.sourceIp}{realEv.port ? `:${realEv.port}` : ''}
                            </span>
                          </div>
                        )}
                        {realEv.destinationIp && (
                          <div className="meta-pair">
                            <span className="meta-key">Destination IP:</span>
                            <span className="meta-val ip-val">{realEv.destinationIp}</span>
                          </div>
                        )}
                        {realEv.process && (
                          <div className="meta-pair">
                            <span className="meta-key">Process:</span>
                            <span className="meta-val proc-val">{realEv.process}</span>
                          </div>
                        )}
                        {realEv.action && (
                          <div className="meta-pair">
                            <span className="meta-key">Action:</span>
                            <span className="meta-val">{realEv.action}</span>
                          </div>
                        )}
                      </div>

                      {/* Original Raw Evidence Payload (Preserved 100% untouched) */}
                      {rawLog && (
                        <div className="audit-raw-block">
                          <div className="raw-header font-mono">
                            <span className="raw-label">ORIGINAL RAW EVIDENCE:</span>
                            <button
                              type="button"
                              className="raw-jump-link font-mono"
                              onClick={() => onEventClick?.(realEv.eventId)}
                            >
                              Inspect in Ledger →
                            </button>
                          </div>
                          <pre className="raw-snippet font-mono">{rawLog}</pre>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="insufficient-evidence-box font-mono">
                <AlertTriangle size={13} className="text-warning" />
                <span>No confirmed events found. This finding represents an unverified hypothesis.</span>
              </div>
            )}
          </div>

          {/* 6. Section 2: AI INFERENCE */}
          <div className="audit-section audit-inference-section">
            <div className="audit-section-label inferred">
              <span className="audit-dot inferred-dot" />
              AI INFERENCE
              <span className="section-subtitle font-mono">Analytical deduction from confirmed evidence — not raw telemetry</span>
            </div>

            <div className="audit-inference-box">
              <p className="audit-inference-text">
                {finding.inferenceNote ||
                 finding.shortExplanation ||
                 'The AI correlated the chronological sequence of confirmed events above to infer attacker intent and attack progression.'}
              </p>

              {finding.missingEvidence && (
                <div className="missing-evidence-note font-mono">
                  <strong>Missing Telemetry:</strong> {finding.missingEvidence}
                </div>
              )}

              {/* Source attribution in AI Inference */}
              <div className="inference-source-attribution font-mono">
                <span className="attr-label">Contributing Source Evidence:</span>
                <span className="attr-files">{sourceFiles.join(', ') || 'No file references'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function FindingsList({ findings = [], events = [], onEventClick }) {
  if (findings.length === 0) return null

  // Map of actual normalized events for O(1) strict verification
  const eventLookup = new Map((events || []).map(e => [e.eventId, e]))

  return (
    <div className="findings-section-wrapper" id="findings-section">
      <div className="section-header-compact">
        <h3 className="section-title">AI FINDINGS</h3>
        <span className="section-count font-mono">{findings.length} findings</span>
      </div>
      <div className="findings-cards-list">
        {findings.map((finding, idx) => (
          <FindingCard
            key={finding.id || idx}
            finding={finding}
            index={idx}
            eventLookup={eventLookup}
            onEventClick={onEventClick}
          />
        ))}
      </div>
    </div>
  )
}
