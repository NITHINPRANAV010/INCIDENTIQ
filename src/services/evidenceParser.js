/**
 * IncidentIQ — Multi-Format Evidence Parser & Normalization Service
 * =================================================================
 * Supports: .log, .txt, .json, .csv
 *
 * Normalizes all evidence into a common event structure:
 * {
 *   eventId: string,
 *   timestamp: string | null,
 *   source: string,
 *   eventType: string,
 *   username: string | null,
 *   sourceIp: string | null,
 *   destinationIp: string | null,
 *   port: string | number | null,
 *   action: string | null,
 *   process: string | null,
 *   message: string,
 *   severity: string | null,
 *   evidenceFile: string,
 *   raw: string
 * }
 *
 * Strict Rules:
 *   - Missing fields remain null/unknown. NEVER invent missing values.
 *   - Every event maintains connection to source file and raw evidence.
 *   - Errors on one file do not crash or block other valid files.
 */

export const SUPPORTED_EXTENSIONS = ['log', 'txt', 'json', 'csv']
export const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 // 5 MB

/**
 * Format byte size into a human-readable string.
 */
export function formatFileSize(bytes) {
  if (typeof bytes === 'string') return bytes
  if (typeof bytes !== 'number' || isNaN(bytes)) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * Validate file metadata before reading or parsing.
 */
export function validateFileMetadata(file) {
  const name = file.name || 'unnamed'
  const ext = (name.split('.').pop() || '').toLowerCase()

  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    return {
      valid: false,
      error: `Unsupported file type. Upload .log, .txt, .json or .csv.`,
    }
  }

  if (file.size === 0) {
    return {
      valid: false,
      error: 'File is empty and cannot be analyzed.',
    }
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `File size exceeds 5 MB limit (${formatFileSize(file.size)}).`,
    }
  }

  return { valid: true, error: null }
}

/**
 * Read browser File/Blob as text.
 */
export function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    if (typeof file === 'string') {
      resolve(file)
      return
    }
    if (file && typeof file.content === 'string') {
      resolve(file.content)
      return
    }
    if (!(file instanceof File || file instanceof Blob)) {
      reject(new Error('Invalid file object.'))
      return
    }
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target.result || '')
    reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`))
    reader.readAsText(file, 'utf-8')
  })
}

/* ============================================================
   1. LOG & TXT PARSER
   ============================================================ */

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g

function parseLogLine(line, filename, _lineIndex) {
  const trimmed = line.trim()
  if (!trimmed) return null

  // Default event model with raw preserved
  const event = {
    eventId: null,
    timestamp: null,
    source: filename,
    eventType: 'log_entry',
    username: null,
    sourceIp: null,
    destinationIp: null,
    port: null,
    action: null,
    process: null,
    message: trimmed,
    severity: 'INFO',
    evidenceFile: filename,
    raw: trimmed,
  }

  // 1. Extract timestamps
  // ISO-8601: 2024-11-15T22:08:14Z or 2024-11-15 22:08:14
  const isoMatch = trimmed.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/)
  if (isoMatch) {
    event.timestamp = isoMatch[0].replace(' ', 'T')
  } else {
    // Syslog timestamp: Nov 15 22:08:14
    const syslogMatch = trimmed.match(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b/i)
    if (syslogMatch) {
      event.timestamp = `${syslogMatch[1]} ${syslogMatch[2]} ${syslogMatch[3]}`
    } else {
      // Time-only: 22:08:14
      const timeMatch = trimmed.match(/\b\d{2}:\d{2}:\d{2}\b/)
      if (timeMatch) {
        event.timestamp = timeMatch[0]
      }
    }
  }

  // 2. Extract IP addresses (source vs destination)
  const srcIpMatch = trimmed.match(/(?:from|SRC=|client(?:\s+ip)?[:=]?)\s*([0-9.]+)/i)
  const dstIpMatch = trimmed.match(/(?:to|DST=|server(?:\s+ip)?[:=]?)\s*([0-9.]+)/i)

  if (srcIpMatch && IPV4_REGEX.test(srcIpMatch[1])) {
    event.sourceIp = srcIpMatch[1]
  }
  if (dstIpMatch && IPV4_REGEX.test(dstIpMatch[1])) {
    event.destinationIp = dstIpMatch[1]
  }

  // Fallback IP extraction if not matched specifically
  if (!event.sourceIp && !event.destinationIp) {
    const ips = trimmed.match(IPV4_REGEX)
    if (ips && ips.length > 0) {
      event.sourceIp = ips[0]
      if (ips.length > 1) {
        event.destinationIp = ips[1]
      }
    }
  }

  // 3. Extract Ports
  const sptMatch = trimmed.match(/(?:SPT=|spt[:=])\s*(\d+)/i)
  const dptMatch = trimmed.match(/(?:DPT=|dpt[:=]|port\s+)(\d+)/i)
  if (dptMatch) {
    event.port = parseInt(dptMatch[1], 10)
  } else if (sptMatch) {
    event.port = parseInt(sptMatch[1], 10)
  }

  // 4. Extract Usernames
  const userMatch = trimmed.match(/(?:for invalid user|for user|user|for)\s+([a-zA-Z0-9._-]+)/i) ||
                    trimmed.match(/USER=([a-zA-Z0-9._-]+)/i) ||
                    trimmed.match(/by\s+([a-zA-Z0-9._-]+)/i) ||
                    trimmed.match(/session opened for user\s+([a-zA-Z0-9._-]+)/i)
  if (userMatch && !['invalid', 'a', 'the', 'from', 'port', 'pts'].includes(userMatch[1].toLowerCase())) {
    event.username = userMatch[1]
  }

  // 5. Extract Process / Service
  const procMatch = trimmed.match(/(?:sshd|sudo|cron|kernel|systemd-logind|audit|nginx|apache2|named)\[\d+\]/i) ||
                    trimmed.match(/comm="?([^"\s]+)"?/i) ||
                    trimmed.match(/exe="?([^"\s]+)"?/i) ||
                    trimmed.match(/COMMAND=([^\s;]+)/i) ||
                    trimmed.match(/process exec:\s*pid=\d+\s*comm="?([^"\s]+)"?/i)
  if (procMatch) {
    event.process = procMatch[1] || procMatch[0].split('[')[0]
  }

  // 6. Classify Event Type, Action, Severity
  const lower = trimmed.toLowerCase()

  if (lower.includes('failed password') || lower.includes('authentication failure') || lower.includes('login failed')) {
    event.eventType = 'authentication_failure'
    event.action = 'failed'
    event.severity = 'HIGH'
  } else if (lower.includes('accepted password') || lower.includes('session opened') || lower.includes('successful login')) {
    event.eventType = 'authentication_success'
    event.action = 'accepted'
    event.severity = lower.includes('root') ? 'MEDIUM' : 'LOW'
  } else if (lower.includes('sudo:') || lower.includes('command=') || lower.includes('session opened for user root')) {
    event.eventType = 'privilege_escalation'
    event.action = 'exec'
    event.severity = 'HIGH'
    if (lower.includes('/etc/shadow') || lower.includes('reverse shell') || lower.includes('nc ')) {
      event.severity = 'CRITICAL'
    }
  } else if (lower.includes('process exec') || lower.includes('apparmor="allowed"') || lower.includes('comm=') || lower.includes('exe=')) {
    event.eventType = 'process_execution'
    event.action = 'exec'
    if (lower.includes('/tmp') || lower.includes('nc ') || lower.includes('wget') || lower.includes('curl') || lower.includes('beacon')) {
      event.severity = 'HIGH'
    } else {
      event.severity = 'MEDIUM'
    }
  } else if (lower.includes('disconnect')) {
    event.eventType = 'session_close'
    event.action = 'disconnected'
    event.severity = 'INFO'
  } else if (lower.includes('outbound_new') || lower.includes('outbound_established') || lower.includes('data_transfer') || /\bconnect(?:ion|ed)?\b/i.test(trimmed)) {
    event.eventType = 'network_connection'
    event.action = lower.includes('data_transfer') ? 'transfer' : 'connect'
    if (lower.includes('4444') || lower.includes('data_transfer') || (event.port && [4444, 1337, 6667, 31337].includes(event.port))) {
      event.severity = 'CRITICAL'
    } else {
      event.severity = 'MEDIUM'
    }
  } else if (lower.includes('inbound_rejected') || lower.includes('drop') || lower.includes('block') || lower.includes('denied')) {
    event.eventType = 'firewall_block'
    event.action = 'blocked'
    event.severity = 'MEDIUM'
  } else if (lower.includes('error') || lower.includes('alert') || lower.includes('warning')) {
    event.eventType = 'security_alert'
    event.severity = lower.includes('error') ? 'HIGH' : 'MEDIUM'
  }

  return event
}

export function parseLogFile(filename, text) {
  const lines = text.split(/\r?\n/)
  const events = []

  lines.forEach((line, idx) => {
    if (!line.trim()) return
    const ev = parseLogLine(line, filename, idx + 1)
    if (ev) events.push(ev)
  })

  return events
}

/* ============================================================
   2. JSON PARSER
   ============================================================ */

export function parseJsonFile(filename, text) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('Invalid JSON evidence. Please check the file format.')
  }

  let items = []
  if (Array.isArray(parsed)) {
    items = parsed
  } else if (typeof parsed === 'object' && parsed !== null) {
    // Check for common wrapped arrays: events, alerts, logs, records, data
    const arrayKey = Object.keys(parsed).find(k => Array.isArray(parsed[k]))
    if (arrayKey) {
      items = parsed[arrayKey]
    } else {
      // Single event object
      items = [parsed]
    }
  } else {
    throw new Error('Invalid JSON evidence. Please check the file format.')
  }

  return items.map((item) => {
    if (typeof item !== 'object' || item === null) {
      return {
        eventId: null,
        timestamp: null,
        source: filename,
        eventType: 'json_record',
        username: null,
        sourceIp: null,
        destinationIp: null,
        port: null,
        action: null,
        process: null,
        message: String(item),
        severity: 'INFO',
        evidenceFile: filename,
        raw: String(item),
      }
    }

    const eventId = item.alert_id || item.alertId || item.event_id || item.eventId || item.id || null
    const timestamp = item.timestamp || item.time || item['@timestamp'] || item.date || item.datetime || item.event_time || null
    const eventType = item.rule || item.eventType || item.event_type || item.type || item.category || item.alert_name || 'security_alert'
    const username = item.user || item.username || item.user_name || item.actor || item.account || (item.user && item.user.name) || null
    const sourceIp = item.source_ip || item.sourceIp || item.src_ip || item.src || (item.source && item.source.ip) || item.client_ip || null
    const destinationIp = item.destination_ip || item.destinationIp || item.dst_ip || item.dst || (item.destination && item.destination.ip) || item.server_ip || null
    const port = item.destination_port || item.dst_port || item.port || item.dpt || item.source_port || item.src_port || null
    const action = item.action || item.status || item.outcome || item.result || null
    const process = item.process || item.process_name || item.exe || item.command || item.cmd || item.parent || null
    const message = item.description || item.message || item.details || item.msg || item.summary || item.rule || 'JSON security event'
    const severity = (item.severity || item.level || item.priority || 'MEDIUM').toUpperCase()

    return {
      eventId,
      timestamp,
      source: filename,
      eventType: String(eventType).toLowerCase(),
      username: username ? String(username) : null,
      sourceIp: sourceIp ? String(sourceIp) : null,
      destinationIp: destinationIp ? String(destinationIp) : null,
      port: port ? (isNaN(port) ? port : parseInt(port, 10)) : null,
      action: action ? String(action).toLowerCase() : null,
      process: process ? String(process) : null,
      message: String(message),
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity) ? severity : 'MEDIUM',
      evidenceFile: filename,
      raw: JSON.stringify(item),
    }
  })
}

/* ============================================================
   3. CSV PARSER
   ============================================================ */

/**
 * Robust CSV line tokenizer that respects quotes and commas within quotes.
 */
function tokenizeCsvLine(line) {
  const result = []
  let cur = ''
  let inQuotes = false

  for (let i = 0; i < line.length; i++) {
    const char = line[i]
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"'
        i++
      } else {
        inQuotes = !inQuotes
      }
    } else if (char === ',' && !inQuotes) {
      result.push(cur.trim())
      cur = ''
    } else {
      cur += char
    }
  }
  result.push(cur.trim())
  return result
}

export function parseCsvFile(filename, text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  if (lines.length < 2) {
    throw new Error('CSV file contains insufficient data (header and rows required).')
  }

  const rawHeaders = tokenizeCsvLine(lines[0])
  const headerMap = {}

  rawHeaders.forEach((h, idx) => {
    const clean = h.toLowerCase().replace(/[^a-z0-9_]/g, '')
    headerMap[clean] = idx
  })

  const findCol = (regex) => {
    const found = Object.keys(headerMap).find(k => regex.test(k))
    return found !== undefined ? headerMap[found] : null
  }

  const timeCol   = findCol(/^(timestamp|time|date|datetime|event_time|created_at)$/i)
  const srcIpCol  = findCol(/^(src_ip|source_ip|src|sourceip|source_address|client_ip)$/i)
  const dstIpCol  = findCol(/^(dst_ip|destination_ip|dst|destinationip|dest_ip|server_ip)$/i)
  const userCol   = findCol(/^(user|username|user_name|actor|account)$/i)
  const typeCol   = findCol(/^(event|event_type|eventtype|type|category|signature|rule)$/i)
  const actCol    = findCol(/^(action|status|result|outcome|disposition)$/i)
  const procCol   = findCol(/^(process|process_name|cmd|command|exe|app|application)$/i)
  const portCol   = findCol(/^(port|dst_port|destination_port|src_port|dpt|spt)$/i)
  const msgCol    = findCol(/^(message|description|details|msg|info|reason|summary)$/i)
  const sevCol    = findCol(/^(severity|level|priority)$/i)

  const events = []

  for (let i = 1; i < lines.length; i++) {
    const row = tokenizeCsvLine(lines[i])
    if (row.length === 0 || (row.length === 1 && !row[0])) continue

    const getVal = (colIdx) => (colIdx !== null && row[colIdx] !== undefined && row[colIdx] !== '') ? row[colIdx] : null

    const timestamp = getVal(timeCol)
    const sourceIp = getVal(srcIpCol)
    const destinationIp = getVal(dstIpCol)
    const username = getVal(userCol)
    const action = getVal(actCol)
    const process = getVal(procCol)
    const rawPort = getVal(portCol)
    const port = rawPort ? (isNaN(rawPort) ? rawPort : parseInt(rawPort, 10)) : null
    const message = getVal(msgCol) || lines[i]
    const rawSev = getVal(sevCol)
    const severity = rawSev ? rawSev.toUpperCase() : 'INFO'

    let eventType = getVal(typeCol)
    if (!eventType) {
      if ((sourceIp && destinationIp) || port || action === 'connect' || action === 'transfer' || (lines[i].toLowerCase().includes('outbound') || lines[i].toLowerCase().includes('inbound'))) {
        eventType = 'network_connection'
      } else if (process || action === 'exec') {
        eventType = 'process_execution'
      } else if (username && (action === 'login' || action === 'failed' || action === 'accepted')) {
        eventType = 'authentication_event'
      } else {
        eventType = 'csv_record'
      }
    }

    events.push({
      eventId: null,
      timestamp,
      source: filename,
      eventType: eventType.toLowerCase(),
      username,
      sourceIp,
      destinationIp,
      port,
      action: action ? action.toLowerCase() : null,
      process,
      message,
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity) ? severity : 'INFO',
      evidenceFile: filename,
      raw: lines[i],
    })
  }

  return events
}

/* ============================================================
   4. FILE INGESTION & DISPATCH
   ============================================================ */

/**
 * Parse a single file content based on extension.
 * Returns { name, type, size, status: 'ok'|'error', events[], error? }
 */
export async function ingestFile(fileOrSample) {
  const name = fileOrSample.name || 'evidence.log'
  const ext = (name.split('.').pop() || '').toLowerCase()
  const size = fileOrSample.size ? formatFileSize(fileOrSample.size) : '0 B'

  // Validation
  const validation = validateFileMetadata(fileOrSample)
  if (!validation.valid) {
    return {
      name,
      type: ext,
      size,
      status: 'error',
      events: [],
      error: validation.error,
    }
  }

  try {
    const text = await readFileAsText(fileOrSample)
    if (!text || !text.trim()) {
      return {
        name,
        type: ext,
        size,
        status: 'error',
        events: [],
        error: 'File is empty and cannot be analyzed.',
      }
    }

    let events = []
    if (ext === 'json') {
      events = parseJsonFile(name, text)
    } else if (ext === 'csv') {
      events = parseCsvFile(name, text)
    } else {
      // .log or .txt
      events = parseLogFile(name, text)
    }

    if (events.length === 0) {
      return {
        name,
        type: ext,
        size,
        status: 'error',
        events: [],
        error: 'No recognizable security events found in file.',
      }
    }

    return {
      name,
      type: ext,
      size,
      status: 'ok',
      events,
      content: text,
      charCount: text.length,
    }
  } catch (err) {
    return {
      name,
      type: ext,
      size,
      status: 'error',
      events: [],
      error: err.message || 'Parsing failed',
    }
  }
}

/**
 * Ingest multiple files, capturing individual errors without blocking valid ones.
 */
export async function ingestFiles(filesList) {
  const results = []
  for (const f of filesList) {
    const parsed = await ingestFile(f)
    results.push(parsed)
  }
  return results
}

/* ============================================================
   5. EVENT NORMALIZATION & TRACEABILITY
   ============================================================ */

/**
 * Normalizes all events from successfully parsed files:
 * - Assigns unique sequential Event IDs with prefixes (AUTH-001, NET-001, etc.)
 * - Sorts chronologically
 * - Preserves evidenceFile and raw evidence
 * - Computes parsing summary
 */
export function normalizeEvents(parsedFiles) {
  const validFiles = parsedFiles.filter(f => f.status === 'ok' && Array.isArray(f.events) && f.events.length > 0)
  const failedFiles = parsedFiles.filter(f => f.status === 'error').map(f => ({ name: f.name, reason: f.error }))

  const counters = {
    AUTH: 1,
    NET: 1,
    PROC: 1,
    ALERT: 1,
    LOG: 1,
    CSV: 1,
  }

  const allEvents = []

  validFiles.forEach(file => {
    file.events.forEach(ev => {
      // Assign prefix if not already structured
      let id = ev.eventId
      if (!id || typeof id !== 'string' || !/^[A-Z]+-\d+$/.test(id)) {
        let prefix = 'LOG'
        const type = (ev.eventType || '').toLowerCase()

        if (type.includes('auth') || type.includes('login') || type.includes('password')) {
          prefix = 'AUTH'
        } else if (type.includes('net') || type.includes('connection') || type.includes('outbound') || type.includes('firewall')) {
          prefix = 'NET'
        } else if (type.includes('proc') || type.includes('exec') || type.includes('sudo') || type.includes('escalation')) {
          prefix = 'PROC'
        } else if (file.type === 'json' || type.includes('alert') || type.includes('rule')) {
          prefix = 'ALERT'
        } else if (file.type === 'csv') {
          prefix = 'CSV'
        }

        const numStr = String(counters[prefix]++).padStart(3, '0')
        id = `${prefix}-${numStr}`
      }

      allEvents.push({
        ...ev,
        eventId: id,
        source: ev.source || file.name,
        evidenceFile: ev.evidenceFile || file.name,
        raw: ev.raw || ev.message || '',
      })
    })
  })

  // Sort chronologically where possible
  allEvents.sort((a, b) => {
    if (!a.timestamp && !b.timestamp) return 0
    if (!a.timestamp) return 1
    if (!b.timestamp) return -1
    const da = new Date(a.timestamp).getTime()
    const db = new Date(b.timestamp).getTime()
    if (!isNaN(da) && !isNaN(db)) return da - db
    return String(a.timestamp).localeCompare(String(b.timestamp))
  })

  // Compute parsing summary metrics
  const summary = {
    filesProcessed: validFiles.length,
    failedFiles,
    totalEvents: allEvents.length,
    authEvents: allEvents.filter(e => e.eventId.startsWith('AUTH-') || (e.eventType || '').includes('auth')).length,
    networkEvents: allEvents.filter(e => e.eventId.startsWith('NET-') || (e.eventType || '').includes('network') || (e.eventType || '').includes('outbound')).length,
    endpointEvents: allEvents.filter(e => e.eventId.startsWith('PROC-') || (e.eventType || '').includes('proc') || (e.eventType || '').includes('sudo')).length,
    alertEvents: allEvents.filter(e => e.eventId.startsWith('ALERT-') || (e.eventType || '').includes('alert')).length,
    otherEvents: 0,
  }
  summary.otherEvents = Math.max(0, summary.totalEvents - (summary.authEvents + summary.networkEvents + summary.endpointEvents + summary.alertEvents))

  return {
    events: allEvents,
    summary,
    validFiles,
    failedFiles,
  }
}

/**
 * Build labeled evidence bundle string for AI context.
 */
export function buildEvidenceBundle(parsedFiles) {
  const validFiles = parsedFiles.filter(f => f.status === 'ok' && f.content && f.content.trim())
  if (validFiles.length === 0) {
    throw new Error('No readable evidence content found. Please check uploaded files.')
  }

  return validFiles.map(f =>
    `${'='.repeat(60)}\nFILE: ${f.name}  |  TYPE: ${f.type.toUpperCase()}  |  SIZE: ${f.size}\n${'='.repeat(60)}\n${f.content.trim()}`
  ).join('\n\n')
}

// Backward-compatible exports for existing codebase
export const parseFile = ingestFile
export const parseFiles = ingestFiles
export function parseSampleFiles(sampleFiles) {
  return sampleFiles.map(f => {
    const ext = (f.name.split('.').pop() || '').toLowerCase()
    let events = []
    try {
      if (ext === 'json') events = parseJsonFile(f.name, f.content)
      else if (ext === 'csv') events = parseCsvFile(f.name, f.content)
      else events = parseLogFile(f.name, f.content)
    } catch {
      events = []
    }
    return {
      name: f.name,
      type: ext,
      size: typeof f.size === 'string' ? f.size : formatFileSize(f.size || 0),
      status: events.length > 0 ? 'ok' : 'warning',
      events,
      content: f.content || '',
      charCount: (f.content || '').length,
    }
  })
}
