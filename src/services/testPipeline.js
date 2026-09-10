import fs from 'fs'
import { parseLogFile, parseJsonFile, parseCsvFile, normalizeEvents } from './evidenceParser.js'
import {
  heuristicThreatClassification,
  heuristicCorrelation,
  heuristicRecommendations,
  PIPELINE_STAGES,
} from './gemini.js'

async function runPipelineTests() {
  console.log('=== STARTING END-TO-END PIPELINE TEST SUITE ===')
  let passed = 0
  let failed = 0

  const assert = (condition, name) => {
    if (condition) {
      console.log(`  [PASS] ${name}`)
      passed++
    } else {
      console.error(`  [FAIL] ${name}`)
      failed++
    }
  }

  // 1. Verify Pipeline Stages Count & Order (Requirement 15)
  assert(PIPELINE_STAGES.length === 7, 'Pipeline has exactly 7 stages')
  const expectedLabels = [
    'Evidence Parsed',
    'Events Extracted',
    'Events Normalized',
    'Threat Patterns Analyzed',
    'Events Correlated',
    'Findings Generated',
    'Investigation Plan Generated',
  ]
  const labelsMatch = PIPELINE_STAGES.every((s, i) => s.label === expectedLabels[i])
  assert(labelsMatch, 'All 7 pipeline stage labels match specification in order')

  // 2. Test Ingestion & Schema Normalization (Requirements 1, 2, 3, 4)
  const test2Text = fs.readFileSync('src/data/testEvidence/test2_failed_logins.log', 'utf-8')
  const test3Text = fs.readFileSync('src/data/testEvidence/test3_privilege_escalation.txt', 'utf-8')
  const test4Text = fs.readFileSync('src/data/testEvidence/test4_network_activity.csv', 'utf-8')
  const test5Text = fs.readFileSync('src/data/testEvidence/test5_combined_incident.json', 'utf-8')

  const parsedBundle = [
    { name: 'auth.log', type: 'log', size: '1 KB', status: 'ok', events: parseLogFile('auth.log', test2Text), content: test2Text },
    { name: 'priv_esc.txt', type: 'txt', size: '1 KB', status: 'ok', events: parseLogFile('priv_esc.txt', test3Text), content: test3Text },
    { name: 'network.csv', type: 'csv', size: '1 KB', status: 'ok', events: parseCsvFile('network.csv', test4Text), content: test4Text },
    { name: 'alerts.json', type: 'json', size: '1 KB', status: 'ok', events: parseJsonFile('alerts.json', test5Text), content: test5Text },
  ]

  const { events, summary: _summary } = normalizeEvents(parsedBundle)
  assert(events.length > 0, `Normalized total of ${events.length} events across 4 file formats`)

  // Schema verification
  const requiredFields = [
    'eventId', 'timestamp', 'source', 'eventType', 'username',
    'sourceIp', 'destinationIp', 'port', 'action', 'process',
    'message', 'severity', 'evidenceFile', 'raw'
  ]
  const allValid = events.every(e => requiredFields.every(f => e[f] !== undefined))
  assert(allValid, 'Every normalized event implements all 14 schema attributes including raw evidence')

  // Threat pattern analysis
  const annotated = heuristicThreatClassification(events)
  assert(annotated.length === events.length, 'Every event classified with threat annotation')
  const threats = annotated.filter(e => e.isSuspicious)
  assert(threats.length > 0, `Identified ${threats.length} suspicious threat patterns`)

  // Multi-event correlation
  const correlationResult = heuristicCorrelation(events, annotated, '')
  const { verdict, findings, timeline, attackChain: _attackChain } = correlationResult

  assert(verdict && verdict.severity === 'CRITICAL', `Verdict severity is CRITICAL (${verdict?.severity})`)
  assert(verdict.keyIndicators?.length > 0, `Verdict contains ${verdict.keyIndicators?.length} key indicators`)
  assert(findings.length >= 3, `Correlated ${findings.length} evidence-backed findings`)

  // Verify Supporting Event IDs (Requirement 8)
  const allEventsMap = new Map(events.map(e => [e.eventId, e]))
  let allSupportingIdsValid = true
  let everyFindingHasIds = true

  for (const f of findings) {
    if (!Array.isArray(f.supportingEventIds) || f.supportingEventIds.length === 0) {
      everyFindingHasIds = false
    }
    for (const sid of f.supportingEventIds) {
      if (!allEventsMap.has(sid)) {
        allSupportingIdsValid = false
      }
    }
  }
  assert(everyFindingHasIds, 'Every finding contains non-empty supportingEventIds')
  assert(allSupportingIdsValid, 'All supportingEventIds strictly map to actual parsed events (zero invented IDs)')

  // Verify Confirmed vs Inferred separation (Requirement 9)
  const inferredFindings = findings.filter(f => f.isInferred)
  const confirmedFindings = findings.filter(f => !f.isInferred)
  assert(inferredFindings.length > 0, `Correctly identified inferred finding(s): ${inferredFindings.map(f => f.title).join(', ')}`)
  assert(confirmedFindings.length > 0, `Correctly identified confirmed finding(s): ${confirmedFindings.map(f => f.title).join(', ')}`)
  assert(inferredFindings.every(f => typeof f.inferenceNote === 'string' && f.inferenceNote.length > 0), 'Every inferred finding includes explanatory inferenceNote')

  // Verify Chronological Timeline (Requirement 12)
  assert(timeline.length === events.length, `Timeline contains all ${timeline.length} normalized events`)
  let timelineChronological = true
  for (let i = 1; i < timeline.length; i++) {
    const prev = new Date(timeline[i - 1].timestamp || 0).getTime()
    const curr = new Date(timeline[i].timestamp || 0).getTime()
    if (!isNaN(prev) && !isNaN(curr) && curr < prev) {
      timelineChronological = false
    }
  }
  assert(timelineChronological, 'Attack timeline is strictly sorted chronologically from normalized events')

  // 5. Test Recommendations (Requirements 13, 14)
  const plan = heuristicRecommendations(findings, events)
  assert(Array.isArray(plan.recommendations) && plan.recommendations.length > 0, `Generated ${plan.recommendations.length} recommendations`)
  const hasImmediate = plan.recommendations.some(r => r.priority === 'IMMEDIATE')
  assert(hasImmediate, 'Prioritized IMMEDIATE containment action directives')
  const recsHaveRelated = plan.recommendations.every(r => r.relatedFindings?.length > 0 && r.relatedEvents?.length > 0)
  assert(recsHaveRelated, 'All recommendations link to actual related findings and events')

  // 6. Test Insufficient Evidence / Baseline Handling (Requirement 11)
  const test1Text = fs.readFileSync('src/data/testEvidence/test1_normal_auth.log', 'utf-8')
  const test1Parsed = [
    { name: 'normal.log', type: 'log', size: '1 KB', status: 'ok', events: parseLogFile('normal.log', test1Text), content: test1Text }
  ]
  const normalNorm = normalizeEvents(test1Parsed)
  const normalAnnotated = heuristicThreatClassification(normalNorm.events)
  const normalCorr = heuristicCorrelation(normalNorm.events, normalAnnotated, '')

  assert(normalCorr.verdict.severity === 'LOW', `Benign logs classified as LOW severity (${normalCorr.verdict.severity})`)
  assert(normalCorr.verdict.incidentType === 'Routine System Telemetry Baseline', `Incident type is Baseline (${normalCorr.verdict.incidentType})`)
  assert(normalCorr.verdict.summary.toLowerCase().includes('insufficient'), `Verdict summary explicitly states evidence is insufficient ("${normalCorr.verdict.summary}")`)
  assert(normalCorr.findings[0].title === 'Baseline Operational Activity Analyzed', 'Generated Baseline Operational Activity finding')

  console.log(`\nPIPELINE TEST RESULTS: ${passed} passed, ${failed} failed.`)
  if (failed > 0) process.exit(1)
}

runPipelineTests().catch(err => {
  console.error('Pipeline test fatal error:', err)
  process.exit(1)
})
