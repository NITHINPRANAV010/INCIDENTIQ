import './StepNav.css'

const STEPS = [
  { num: '01', id: 'evidence', label: 'EVIDENCE', sub: 'Artifact ingestion' },
  { num: '02', id: 'analysis', label: 'ANALYSIS', sub: 'Correlation pipeline' },
  { num: '03', id: 'findings', label: 'FINDINGS', sub: 'Grounded insights' },
  { num: '04', id: 'response', label: 'RESPONSE', sub: 'Timeline & actions' },
]

export default function StepNav({ currentStep, completedSteps = [], onStepClick, investigation }) {
  return (
    <aside className="step-nav-zone" aria-label="Investigation workflow">
      <div className="step-nav-header font-mono">INVESTIGATION WORKSPACE</div>

      <nav className="step-nav-list">
        {STEPS.map((step) => {
          const isActive = currentStep === step.id
          const isCompleted = completedSteps.includes(step.id)
          const isLocked = !isCompleted && !isActive && currentStep === 'evidence' && step.id !== 'evidence'

          return (
            <div
              key={step.id}
              className={`step-nav-item ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''} ${isLocked ? 'locked' : ''}`}
              onClick={() => !isLocked && onStepClick?.(step.id)}
              role="button"
              tabIndex={isLocked ? -1 : 0}
            >
              <div className="step-nav-indicator font-mono">
                {isCompleted ? '✓' : step.num}
              </div>
              <div className="step-nav-text">
                <span className="step-nav-name">{step.label}</span>
                <span className="step-nav-sub">{step.sub}</span>
              </div>
              {isActive && <div className="step-nav-active-bar" />}
            </div>
          )
        })}
      </nav>

      {/* Compact context block if investigation exists */}
      {investigation && (
        <div className="step-nav-context font-mono">
          <div className="context-label">SESSION CONTEXT</div>
          <div className="context-row">
            <span className="context-key">ID:</span>
            <span className="context-val text-accent">{investigation.id}</span>
          </div>
          <div className="context-row">
            <span className="context-key">FILES:</span>
            <span className="context-val">{investigation.files?.length || 0}</span>
          </div>
          <div className="context-row">
            <span className="context-key">STATUS:</span>
            <span className="context-val">{investigation.status?.toUpperCase()}</span>
          </div>
        </div>
      )}
    </aside>
  )
}
