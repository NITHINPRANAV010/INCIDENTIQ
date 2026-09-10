/**
 * IncidentIQ — Report Builder
 * Assembles investigation data into a structured IR report object.
 * Does NOT add or invent content — only organizes existing analysis data.
 */

export function buildReport(investigation, reportContent) {
  const { id, name, description, analysisResult, recommendations, files, createdAt } = investigation

  const now = new Date().toISOString()
  const verdict = analysisResult?.verdict || {}
  const findings = analysisResult?.findings || []
  const timeline = analysisResult?.timeline || []

  // Categorize findings
  const confirmedFindings = findings.filter(f => !f.isInferred)
  const suspectedActivity = findings.filter(f => f.isInferred)

  // Extract IOCs from findings and events
  const events = analysisResult?.events || []
  const ips = new Set()
  const processes = new Set()

  events.forEach(e => {
    if (e.sourceIp) ips.add(e.sourceIp)
    if (e.destinationIp) ips.add(e.destinationIp)
  })

  return {
    // Metadata
    reportId: `RPT-${id}`,
    incidentId: id,
    incidentName: name,
    classification: verdict.incidentType || 'Security Incident',
    severity: verdict.severity || 'UNKNOWN',
    confidence: verdict.confidence || 0,
    generatedAt: now,
    incidentDate: createdAt,

    // Content
    description,
    executiveSummary: reportContent?.executiveSummary || verdict.summary || '',
    affectedAssets: reportContent?.affectedAssets || [],
    evidenceSummary: reportContent?.evidenceSummary || `${files?.length || 0} evidence files analyzed.`,

    // Findings
    attackTimeline: timeline,
    confirmedFindings: reportContent?.confirmedFindings || confirmedFindings.map(f => f.title),
    suspectedActivity: reportContent?.suspectedActivity || suspectedActivity.map(f => f.title),
    findings: findings,

    // IOCs
    ioc: reportContent?.ioc || {
      ipAddresses: [...ips],
      processes: [...processes],
      files: [],
      domains: [],
    },

    // Recommendations
    recommendations: recommendations || [],

    // AI metadata
    aiConfidence: reportContent?.aiConfidence || verdict.confidence || 0,
    limitations: reportContent?.limitations || 'Analysis is based solely on the provided evidence. Additional evidence sources may reveal further findings.',
    evidenceFiles: files?.map(f => f.name) || [],
  }
}

/**
 * Format a report as plain text for display/download.
 */
export function formatReportAsText(report) {
  const lines = []
  const divider = '═'.repeat(70)
  const line = '─'.repeat(70)

  lines.push(divider)
  lines.push('INCIDENT RESPONSE REPORT')
  lines.push(`IncidentIQ — AI-Powered Cyber Incident Response`)
  lines.push(divider)
  lines.push('')
  lines.push(`Incident ID:       ${report.incidentId}`)
  lines.push(`Report ID:         ${report.reportId}`)
  lines.push(`Classification:    ${report.classification}`)
  lines.push(`Severity:          ${report.severity}`)
  lines.push(`AI Confidence:     ${report.confidence}%`)
  lines.push(`Generated:         ${new Date(report.generatedAt).toLocaleString()}`)
  lines.push(`Incident Date:     ${new Date(report.incidentDate).toLocaleString()}`)
  lines.push('')
  lines.push(line)
  lines.push('EXECUTIVE SUMMARY')
  lines.push(line)
  lines.push(report.executiveSummary || 'Not available.')
  lines.push('')

  if (report.affectedAssets?.length) {
    lines.push(line)
    lines.push('AFFECTED ASSETS')
    lines.push(line)
    report.affectedAssets.forEach(a => lines.push(`  • ${a}`))
    lines.push('')
  }

  lines.push(line)
  lines.push('EVIDENCE SUMMARY')
  lines.push(line)
  lines.push(report.evidenceSummary)
  lines.push(`Files analyzed: ${report.evidenceFiles?.join(', ')}`)
  lines.push('')

  if (report.attackTimeline?.length) {
    lines.push(line)
    lines.push('ATTACK TIMELINE')
    lines.push(line)
    report.attackTimeline.forEach(e => {
      lines.push(`  ${e.displayTime || e.timestamp}  [${e.eventId}]  ${e.description}`)
    })
    lines.push('')
  }

  if (report.confirmedFindings?.length) {
    lines.push(line)
    lines.push('CONFIRMED FINDINGS')
    lines.push(line)
    report.confirmedFindings.forEach((f, i) => lines.push(`  ${i + 1}. ${f}`))
    lines.push('')
  }

  if (report.suspectedActivity?.length) {
    lines.push(line)
    lines.push('SUSPECTED ACTIVITY (INFERENCE)')
    lines.push(line)
    report.suspectedActivity.forEach((f, i) => lines.push(`  ${i + 1}. ${f}`))
    lines.push('')
  }

  if (report.ioc) {
    lines.push(line)
    lines.push('INDICATORS OF COMPROMISE (IOC)')
    lines.push(line)
    if (report.ioc.ipAddresses?.length) {
      lines.push('  IP Addresses:')
      report.ioc.ipAddresses.forEach(ip => lines.push(`    • ${ip}`))
    }
    if (report.ioc.processes?.length) {
      lines.push('  Processes:')
      report.ioc.processes.forEach(p => lines.push(`    • ${p}`))
    }
    if (report.ioc.files?.length) {
      lines.push('  Files:')
      report.ioc.files.forEach(f => lines.push(`    • ${f}`))
    }
    lines.push('')
  }

  if (report.recommendations?.length) {
    lines.push(line)
    lines.push('RECOMMENDED RESPONSE ACTIONS')
    lines.push(line)
    report.recommendations.forEach((r, i) => {
      lines.push(`  ${i + 1}. [${r.priority}] ${r.action}`)
      lines.push(`     Reason: ${r.reason}`)
      if (r.expectedOutcome) lines.push(`     Expected: ${r.expectedOutcome}`)
      lines.push('')
    })
  }

  lines.push(line)
  lines.push('AI CONFIDENCE & LIMITATIONS')
  lines.push(line)
  lines.push(`Overall AI Confidence: ${report.aiConfidence}%`)
  lines.push('')
  lines.push(report.limitations)
  lines.push('')
  lines.push(divider)
  lines.push('END OF REPORT — Generated by IncidentIQ AI Incident Response')
  lines.push(divider)

  return lines.join('\n')
}
