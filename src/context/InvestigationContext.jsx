import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'

const InvestigationContext = createContext(null)

const STORAGE_KEY = 'incidentiq_investigations'
const REPORTS_KEY = 'incidentiq_reports'

function generateId(prefix = 'INC') {
  const num = Math.floor(1000 + Math.random() * 9000)
  return `${prefix}-${num}`
}

// Deep-clone to avoid localStorage parse issues
function safeClone(obj) {
  try { return JSON.parse(JSON.stringify(obj)) } catch { return obj }
}

export function InvestigationProvider({ children }) {
  const [investigations, setInvestigations] = useState(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      return stored ? JSON.parse(stored) : []
    } catch { return [] }
  })

  const [reports, setReports] = useState(() => {
    try {
      const stored = localStorage.getItem(REPORTS_KEY)
      return stored ? JSON.parse(stored) : []
    } catch { return [] }
  })

  const [activeInvestigationId, setActiveInvestigationId] = useState(null)

  // Use a ref so we can access current investigations synchronously
  const investigationsRef = useRef(investigations)
  useEffect(() => { investigationsRef.current = investigations }, [investigations])

  // Persist to localStorage
  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(investigations)) } catch {}
  }, [investigations])

  useEffect(() => {
    try { localStorage.setItem(REPORTS_KEY, JSON.stringify(reports)) } catch {}
  }, [reports])

  const createInvestigation = useCallback(({ name, description, files }) => {
    const id = generateId('INC')
    const now = new Date().toISOString()
    const investigation = {
      id,
      name,
      description,
      // files: array of { name, type, size } — metadata only, no raw content in storage
      files: files || [],
      events: [],
      analysisResult: null,  // { verdict, findings, timeline, attackChain }
      recommendations: [],
      report: null,
      status: 'idle',       // idle | analyzing | complete | error
      createdAt: now,
      updatedAt: now,
    }
    setInvestigations(prev => [investigation, ...prev])
    setActiveInvestigationId(id)
    return id
  }, [])

  const updateInvestigation = useCallback((id, updates) => {
    const cloned = safeClone(updates)
    setInvestigations(prev => prev.map(inv =>
      inv.id === id
        ? { ...inv, ...cloned, updatedAt: new Date().toISOString() }
        : inv
    ))
    // Also update ref synchronously for immediate reads
    investigationsRef.current = investigationsRef.current.map(inv =>
      inv.id === id
        ? { ...inv, ...cloned, updatedAt: new Date().toISOString() }
        : inv
    )
  }, [])

  // Always reads from ref to avoid stale closures
  const getInvestigation = useCallback((id) => {
    return investigationsRef.current.find(inv => inv.id === id) || null
  }, [])

  const saveReport = useCallback((investigation) => {
    // Derive severity from analysisResult.verdict (not analysisResult.severity)
    const severity = investigation.analysisResult?.verdict?.severity
                  || investigation.analysisResult?.severity
                  || investigation.report?.severity
                  || null

    const report = {
      ...safeClone(investigation.report),
      incidentId: investigation.id,
      incidentName: investigation.name,
      severity,
      confidence: investigation.analysisResult?.verdict?.confidence || investigation.report?.confidence || 0,
      savedAt: new Date().toISOString(),
    }
    setReports(prev => {
      const existing = prev.findIndex(r => r.incidentId === investigation.id)
      if (existing >= 0) {
        const updated = [...prev]
        updated[existing] = report
        return updated
      }
      return [report, ...prev]
    })
    return report
  }, [])

  const deleteInvestigation = useCallback((id) => {
    setInvestigations(prev => prev.filter(inv => inv.id !== id))
    investigationsRef.current = investigationsRef.current.filter(inv => inv.id !== id)
    if (activeInvestigationId === id) setActiveInvestigationId(null)
  }, [activeInvestigationId])

  // Derived stats — always read from live state
  const stats = {
    total: investigations.length,
    active: investigations.filter(i => i.status === 'analyzing' || i.status === 'idle').length,
    critical: investigations.filter(i =>
      (i.analysisResult?.verdict?.severity || i.analysisResult?.severity) === 'CRITICAL'
    ).length,
    evidenceItems: investigations.reduce((sum, i) => sum + (i.files?.length || 0), 0),
    completed: investigations.filter(i => i.status === 'complete').length,
  }

  return (
    <InvestigationContext.Provider value={{
      investigations,
      reports,
      activeInvestigationId,
      setActiveInvestigationId,
      createInvestigation,
      updateInvestigation,
      getInvestigation,
      saveReport,
      deleteInvestigation,
      stats,
    }}>
      {children}
    </InvestigationContext.Provider>
  )
}

export function useInvestigation() {
  const ctx = useContext(InvestigationContext)
  if (!ctx) throw new Error('useInvestigation must be used within InvestigationProvider')
  return ctx
}
