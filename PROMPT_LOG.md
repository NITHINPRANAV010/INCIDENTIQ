# IncidentIQ — Prompt Log
## AI Catalyst '26 | PS-32 Cyber Incident Response Assistant

This document transparently records all AI prompts used during IncidentIQ's development,
per hackathon judging criteria on prompt engineering quality.

---

## Pipeline Overview

```
RAW EVIDENCE
    ↓
STAGE 1: Evidence Extraction
    ↓
STAGE 2: Threat Analysis
    ↓
STAGE 3: Event Correlation + Finding Generation
    ↓
STAGE 4: Investigation Planning
    ↓
STAGE 5: Report Generation
```

---

## STAGE 1 — Evidence Extraction

**Purpose:** Convert raw, unstructured log files into structured security events.

**Task Being Solved:**
Raw logs come in free-text formats (syslog, auth.log, JSON alerts, etc.).
The AI must extract meaningful events without fabricating data not present in the evidence.

**System Prompt:**
```
You are an expert cybersecurity incident response analyst specializing in log analysis and SIEM event correlation.

Your task is to extract structured security events from raw log files and security alerts.

CRITICAL RULES:
- Extract ONLY events that are actually present in the provided evidence
- Do NOT invent, fabricate, or hallucinate any events, IP addresses, usernames, or timestamps
- Assign sequential event IDs with prefixes based on type: AUTH- (authentication), PROC- (process), NET- (network), ALERT- (IDS/SIEM alerts)
- Use exact timestamps from the logs where available
- If a timestamp is not in ISO format, convert it to ISO 8601

Return ONLY valid JSON matching this exact schema...
```

**Expected Output:** Structured JSON array of security events with IDs, timestamps, types, actors, IPs.

**Key Design Decisions:**
- Event ID prefix system (AUTH-, PROC-, NET-, ALERT-) creates traceable references
- Group repeated identical events (e.g., 47 failed logins → 1 event with count field)
- ISO 8601 normalization ensures timeline chronology
- Explicit "do not fabricate" instruction repeated to prevent hallucination

**Validation Observations:**
- Gemini 2.0 Flash correctly groups repeated login failures
- Accurately extracts source IPs, usernames, timestamps from syslog format
- Does not invent events when logs are sparse

---

## STAGE 2 — Threat Analysis

**Purpose:** Classify each extracted event by threat type and annotate with threat context.

**Task Being Solved:**
Raw events are neutral — they don't carry threat meaning. This stage adds threat classification
without adding new evidence.

**System Prompt:**
```
You are a cybersecurity threat analyst. Analyze a list of structured security events and classify each one by threat type and severity.

CRITICAL RULES:
- Only reference events by their exact IDs from the input
- Do not add events that were not in the input
- Separate confirmed facts from inferences using the isInferred field
...
```

**Expected Output:** Each event annotated with threatType, severity, isSuspicious, isInferred, threatNote.

**Key Design Decisions:**
- `isInferred` field explicitly separates confirmed evidence from AI reasoning
- Confidence is per-annotation, not global
- Threat type vocabulary controlled: brute_force, credential_compromise, privilege_escalation, etc.

---

## STAGE 3 — Event Correlation + Finding Generation (Core Stage)

**Purpose:** Cross-source event correlation, attack chain reconstruction, named findings with evidence references, timeline, incident verdict.

**Task Being Solved:**
This is the core differentiator — linking AUTH-042 → AUTH-043 → PROC-019 → NET-002 into a
coherent attack story and generating traceable findings.

**System Prompt Key Instructions:**
```
1. Correlate related events across different sources to identify attack chains
2. Generate named, evidence-backed findings with confidence scores
3. Produce an overall incident verdict
4. Reconstruct the chronological attack timeline

CRITICAL RULES:
- Every finding MUST reference the exact event IDs from the input that support it
- NEVER fabricate event IDs, IP addresses, usernames, or timestamps not present in the input
- Separate confirmed facts (directly evidenced) from inferences (logically deduced)
- Confidence scores must reflect actual evidence strength (0-100)
```

**Expected Output Schema:**
```json
{
  "verdict": {
    "severity": "CRITICAL",
    "incidentType": "...",
    "confidence": 94,
    "summary": "...",
    "keyIndicators": [...]
  },
  "findings": [
    {
      "id": "FIND-001",
      "title": "...",
      "severity": "HIGH",
      "confidence": 97,
      "shortExplanation": "...",
      "isInferred": false,
      "supportingEvents": [
        { "eventId": "AUTH-001", "description": "...", "contributionNote": "..." }
      ],
      "inferenceNote": null
    }
  ],
  "timeline": [...],
  "attackChain": [...]
}
```

**Key Design Decisions:**
- `supportingEvents` array per finding forces AI to cite evidence
- `isInferred` at finding level separates confirmed from suspected
- `confidence` is per-finding to reflect evidence quality
- `attackChain` provides structured step-by-step progression (Brute Force → Compromise → Escalation)

**Validation Observations:**
- For INC-1024 sample: correctly identifies 47 failed logins + successful login as brute-force pattern
- Correctly correlates NET-002 (port 4444 outbound) with PROC-019 (nc reverse shell process)
- Confidence scores ranged 87-97% for confirmed, 72-84% for inferred findings
- No fabricated event IDs observed in testing

---

## STAGE 4 — Investigation Planning

**Purpose:** Generate prioritized, actionable investigation and response recommendations grounded in the findings.

**Task Being Solved:**
After analysis, analysts need a clear list of what to do next — ordered by urgency.
Recommendations must be grounded in findings, not generic IR checklists.

**System Prompt Key Instruction:**
```
CRITICAL RULES:
- Generate recommendations ONLY based on the findings and events provided
- Do not recommend actions unrelated to the identified findings
- Reference relevant finding IDs and event IDs in each recommendation
- Clearly mark these as RECOMMENDATIONS — do NOT claim actions have been taken
- Priority levels: IMMEDIATE, HIGH, MEDIUM, LOW
```

**Expected Output:** Prioritized list with action, reason, relatedFindings[], relatedEvents[], expectedOutcome.

**Key Design Decisions:**
- References to finding IDs and event IDs make recommendations traceable
- Explicit "do NOT claim actions have been taken" prevents AI from asserting containment
- Priority system maps to analyst workflow: IMMEDIATE = now, HIGH = within hours, MEDIUM = within 24h

---

## STAGE 5 — Report Generation

**Purpose:** Create a professional incident response report from the investigation data.

**Task Being Solved:**
The analyst needs a shareable, professional report. The AI must synthesize all prior stages
into a coherent narrative without introducing facts not in the evidence.

**System Prompt Key Instructions:**
```
CRITICAL RULES:
- Use ONLY information from the provided investigation data
- Do NOT introduce facts, IPs, usernames, or events not in the input
- Clearly separate confirmed findings from suspected activity
- Limitations section must honestly acknowledge gaps in evidence
```

**Expected Output:** executiveSummary, affectedAssets, confirmedFindings, suspectedActivity, ioc, limitations, aiConfidence.

**Key Design Decisions:**
- Limitations section is mandatory — forces honest acknowledgment of evidence gaps
- aiConfidence field preserves the confidence from Stage 3 verdict
- Separate confirmed vs. suspected sections mirrors IR report best practices

---

## Prompt Engineering Principles Applied

| Principle | Implementation |
|---|---|
| No fabrication | Explicit instruction in every stage prompt |
| Structured outputs | `responseMimeType: 'application/json'` in every API call |
| Evidence references | Every finding requires `supportingEvents[]` with exact event IDs |
| Fact vs inference | `isInferred` field on every finding |
| Confidence levels | Per-finding confidence 0-100 |
| Controlled vocabulary | Threat types, severity levels, priority levels all enumerated in prompts |
| Temperature | Set to 0.1 for all stages to minimize hallucination |
| Role priming | Each stage begins with specific expert role ("You are a senior cybersecurity incident response analyst...") |

---

## Known Limitations

1. **Evidence size**: Large log files may exceed token limits. Future: chunked processing.
2. **Timestamp parsing**: Unusual log formats may lose timestamp precision.
3. **Confidence calibration**: Confidence percentages are AI estimates, not statistically calibrated.
4. **Single model**: All stages use Gemini 2.0 Flash. Specialized models per stage could improve quality.
5. **No memory**: Each analysis is independent — no cross-investigation correlation.
