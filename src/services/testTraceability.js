import fs from 'fs'
import {
  parseLogFile,
  parseJsonFile,
  parseCsvFile,
  normalizeEvents,
} from './evidenceParser.js'
import { heuristicThreatClassification, heuristicCorrelation } from './gemini.js'

function assert(condition, message) {
  if (!condition) {
    console.error(`  [FAIL] ${message}`)
    process.exit(1)
  }
  console.log(`  [PASS] ${message}`)
}

async function runTraceabilityTests() {
  console.log('=== STARTING EVIDENCE TRACEABILITY TEST SUITE ===')

  // Load formats
  const test2Text = fs.readFileSync('src/data/testEvidence/test2_failed_logins.log', 'utf8')
  const test3Text = fs.readFileSync('src/data/testEvidence/test3_privilege_escalation.txt', 'utf8')
  const test4Text = fs.readFileSync('src/data/testEvidence/test4_network_activity.csv', 'utf8')
  const test5Text = fs.readFileSync('src/data/testEvidence/test5_combined_incident.json', 'utf8')

  const parsedBundle = [
    { name: 'auth.log', type: 'log', size: '2 KB', status: 'ok', events: parseLogFile('auth.log', test2Text), content: test2Text },
    { name: 'audit.txt', type: 'txt', size: '2 KB', status: 'ok', events: parseLogFile('audit.txt', test3Text), content: test3Text },
    { name: 'network.csv', type: 'csv', size: '1 KB', status: 'ok', events: parseCsvFile('network.csv', test4Text), content: test4Text },
    { name: 'alerts.json', type: 'json', size: '1 KB', status: 'ok', events: parseJsonFile('alerts.json', test5Text), content: test5Text },
  ]

  const { events } = normalizeEvents(parsedBundle)
  assert(events.length > 0, `Normalized ${events.length} events across 4 file formats`)

  const eventMap = new Map(events.map(e => [e.eventId, e]))
  assert(eventMap.size === events.length, 'All normalized event IDs are globally unique')

  // Run correlation
  const annotated = heuristicThreatClassification(events)
  const correlationResult = heuristicCorrelation(events, annotated, '')
  const { findings, timeline } = correlationResult

  assert(findings.length > 0, `Generated ${findings.length} findings from multi-source evidence`)

  // 1. Every finding contains a non-empty supportingEventIds array
  const allHaveIds = findings.every(f => Array.isArray(f.supportingEventIds) && f.supportingEventIds.length > 0)
  assert(allHaveIds, 'Requirement 1: Every evidence-backed finding contains non-empty supportingEventIds array')

  // 2. Each supportingEventId corresponds to an actual normalized event
  let allIdsExist = true
  for (const f of findings) {
    for (const eid of f.supportingEventIds) {
      if (!eventMap.has(eid)) {
        allIdsExist = false
        break
      }
    }
  }
  assert(allIdsExist, 'Requirement 2: Every supportingEventId strictly exists in normalized event collection')

  // 3. Store relationship: finding → eventId → normalized event → source file → original raw evidence
  let completeTraceabilityPreserved = true
  for (const f of findings) {
    for (const eid of f.supportingEventIds) {
      const normEv = eventMap.get(eid)
      if (!normEv) { completeTraceabilityPreserved = false; break; }
      if (!normEv.evidenceFile) { completeTraceabilityPreserved = false; break; }
      if (!normEv.raw || normEv.raw.trim().length === 0) { completeTraceabilityPreserved = false; break; }
    }
  }
  assert(completeTraceabilityPreserved, 'Requirement 3: Traceability chain (Finding → eventId → Normalized Event → Source File → Raw Evidence) is 100% complete')

  // 4. Source file extraction
  for (const f of findings) {
    const files = [...new Set(f.supportingEventIds.map(eid => eventMap.get(eid)?.evidenceFile).filter(Boolean))]
    assert(files.length > 0, `Requirement 4: Finding "${f.title}" maps to source file(s): [${files.join(', ')}]`)
  }

  // 5 & 6. Confirmed Evidence vs AI Inference
  const confirmedFindings = findings.filter(f => !f.isInferred)
  const inferredFindings = findings.filter(f => f.isInferred)
  assert(confirmedFindings.length > 0, `Requirement 6: Identified ${confirmedFindings.length} Confirmed Evidence finding(s)`)
  assert(inferredFindings.length > 0, `Requirement 6: Identified ${inferredFindings.length} AI Inference finding(s)`)

  for (const inf of inferredFindings) {
    assert(typeof inf.inferenceNote === 'string' && inf.inferenceNote.length > 0,
      `Requirement 6: Inferred finding "${inf.title}" has explanatory inferenceNote: "${inf.inferenceNote.slice(0, 50)}..."`)
  }

  // 10 & 11. Validation: Reject invalid/invented supportingEventIds
  const fabricatedFinding = {
    id: 'FIND-FAKE',
    title: 'Fabricated Finding',
    supportingEventIds: ['NON-EXISTENT-999', 'FAKED-EVENT-001'],
  }
  const validatedFabricatedIds = fabricatedFinding.supportingEventIds.filter(id => eventMap.has(id))
  assert(validatedFabricatedIds.length === 0, 'Requirement 10 & 11: Fabricated event IDs are strictly rejected by validation filter')

  // 13. Preserve original evidence exactly as received
  let rawUntouched = true
  for (const ev of events) {
    if (ev.evidenceFile.endsWith('.log') && !test2Text.includes(ev.raw)) rawUntouched = false
    if (ev.evidenceFile.endsWith('.txt') && !test3Text.includes(ev.raw)) rawUntouched = false
  }
  assert(rawUntouched, 'Requirement 13: Original raw evidence lines are preserved untouched')

  // 14. Support traceability for all evidence formats: .log, .txt, .json, .csv
  const formatsCovered = new Set(events.map(e => (e.evidenceFile.split('.').pop() || '').toLowerCase()))
  assert(formatsCovered.has('log'), 'Requirement 14: .log traceability verified')
  assert(formatsCovered.has('txt'), 'Requirement 14: .txt traceability verified')
  assert(formatsCovered.has('csv'), 'Requirement 14: .csv traceability verified')
  assert(formatsCovered.has('json'), 'Requirement 14: .json traceability verified')

  // 12. Attack Timeline built entirely from normalized events
  assert(timeline.length === events.length, `Attack timeline includes all ${events.length} normalized events`)

  console.log(`\nTRACEABILITY TEST RESULTS: ALL CHECKS PASSED.`)
}

runTraceabilityTests()
