import fs from 'fs'
import {
  parseLogFile,
  parseJsonFile,
  parseCsvFile,
  validateFileMetadata,
  normalizeEvents
} from './evidenceParser.js'

async function runTests() {
  console.log('=== STARTING EVIDENCE PARSER TEST SUITE ===')
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

  // 1. Validation test
  const validMeta = validateFileMetadata({ name: 'auth.log', size: 1024 })
  assert(validMeta.valid === true, 'Valid file metadata accepted')

  const invalidExt = validateFileMetadata({ name: 'malware.exe', size: 1024 })
  assert(invalidExt.valid === false && invalidExt.error.includes('Unsupported file type'), 'Unsupported .exe rejected with clear error')

  const emptyMeta = validateFileMetadata({ name: 'empty.log', size: 0 })
  assert(emptyMeta.valid === false && emptyMeta.error.includes('File is empty'), 'Empty file rejected with clear error')

  // 2. Test 1: Normal auth log
  const test1Text = fs.readFileSync('src/data/testEvidence/test1_normal_auth.log', 'utf-8')
  const test1Events = parseLogFile('test1_normal_auth.log', test1Text)
  assert(test1Events.length === 6, `Test 1 extracted 6 events (got ${test1Events.length})`)
  assert(test1Events[0].username === 'alice' && test1Events[0].sourceIp === '10.0.2.15', 'Test 1 extracted username and source IP')
  assert(test1Events[0].raw.includes('Accepted publickey'), 'Test 1 preserved raw evidence line')

  // 3. Test 2: Failed logins followed by success
  const test2Text = fs.readFileSync('src/data/testEvidence/test2_failed_logins.log', 'utf-8')
  const test2Events = parseLogFile('test2_failed_logins.log', test2Text)
  assert(test2Events.length === 8, `Test 2 extracted 8 events (got ${test2Events.length})`)
  const failures = test2Events.filter(e => e.eventType === 'authentication_failure')
  const successes = test2Events.filter(e => e.eventType === 'authentication_success')
  assert(failures.length === 6 && successes.length >= 1, `Test 2 identified 6 failures and successful login`)

  // 4. Test 3: Privilege escalation
  const test3Text = fs.readFileSync('src/data/testEvidence/test3_privilege_escalation.txt', 'utf-8')
  const test3Events = parseLogFile('test3_privilege_escalation.txt', test3Text)
  assert(test3Events.length >= 5, `Test 3 extracted events from .txt file (got ${test3Events.length})`)
  const privEsc = test3Events.filter(e => e.eventType === 'privilege_escalation')
  assert(privEsc.length >= 3, `Test 3 correctly classified privilege escalation events`)

  // 5. Test 4: Network CSV
  const test4Text = fs.readFileSync('src/data/testEvidence/test4_network_activity.csv', 'utf-8')
  const test4Events = parseCsvFile('test4_network_activity.csv', test4Text)
  assert(test4Events.length === 4, `Test 4 extracted 4 CSV events (got ${test4Events.length})`)
  assert(test4Events[0].destinationIp === '185.234.219.18' && test4Events[0].port === 4444, 'Test 4 correctly parsed IP and port')
  assert(test4Events[0].raw.includes('4444'), 'Test 4 preserved raw CSV row')

  // 6. Test 5: Combined JSON
  const test5Text = fs.readFileSync('src/data/testEvidence/test5_combined_incident.json', 'utf-8')
  const test5Events = parseJsonFile('test5_combined_incident.json', test5Text)
  assert(test5Events.length === 5, `Test 5 extracted 5 JSON alert events (got ${test5Events.length})`)
  assert(test5Events[0].eventId === 'ALERT-101', 'Test 5 preserved alert_id')
  assert(test5Events[0].evidenceFile === 'test5_combined_incident.json', 'Test 5 linked evidenceFile')

  // 7. Error handling: Malformed JSON
  try {
    parseJsonFile('broken.json', '{ "broken": ')
    assert(false, 'Malformed JSON should have thrown')
  } catch (err) {
    assert(err.message.includes('Invalid JSON evidence'), 'Malformed JSON caught with descriptive error')
  }

  // 8. Error handling: Malformed CSV
  try {
    parseCsvFile('broken.csv', 'only_one_line_no_data')
    assert(false, 'Malformed CSV should have thrown')
  } catch (err) {
    assert(err.message.includes('insufficient data'), 'Malformed CSV caught with descriptive error')
  }

  // 9. Ingest & Normalize Multi-file bundle
  const parsedFiles = [
    { name: 'test2_failed_logins.log', type: 'log', size: '1 KB', status: 'ok', events: test2Events, content: test2Text },
    { name: 'test4_network_activity.csv', type: 'csv', size: '1 KB', status: 'ok', events: test4Events, content: test4Text },
    { name: 'test5_combined_incident.json', type: 'json', size: '1 KB', status: 'ok', events: test5Events, content: test5Text },
    { name: 'corrupted.json', type: 'json', size: '100 B', status: 'error', events: [], error: 'Invalid JSON evidence. Please check the file format.' }
  ]

  const normalized = normalizeEvents(parsedFiles)
  assert(normalized.validFiles.length === 3, 'Normalized 3 valid files')
  assert(normalized.failedFiles.length === 1, 'Tracked 1 failed file')
  assert(normalized.events.length === (test2Events.length + test4Events.length + test5Events.length), `All events combined (${normalized.events.length})`)
  assert(normalized.summary.authEvents > 0, `Summary counts auth events (${normalized.summary.authEvents})`)
  assert(normalized.summary.networkEvents > 0, `Summary counts network events (${normalized.summary.networkEvents})`)

  console.log(`\nRESULTS: ${passed} passed, ${failed} failed.`)
  if (failed > 0) process.exit(1)
}

runTests().catch(err => {
  console.error('Fatal test error:', err)
  process.exit(1)
})
