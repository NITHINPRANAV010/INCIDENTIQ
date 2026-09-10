import { useEffect, useRef } from 'react'
import { AlertCircle } from 'lucide-react'
import { PIPELINE_STAGES } from '../../services/gemini'
import './AnalysisPipeline.css'

export default function AnalysisPipeline({ stages = [] }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [stages])

  const getStageStatus = (key) => {
    const s = stages.find(s => s.stageKey === key)
    return s?.status || 'pending' // pending | running | complete | error
  }

  const hasError = stages.some(s => s.status === 'error')
  const errorStage = stages.find(s => s.status === 'error')

  return (
    <div className="pipeline-panel animate-fade-in">
      <div className="pipeline-header-row">
        <h3 className="pipeline-title">INCIDENT ANALYSIS</h3>
        <span className="pipeline-subtitle font-mono">Telemetry & Evidence Correlation</span>
      </div>

      <div className="pipeline-step-list">
        {PIPELINE_STAGES.map((stageDef) => {
          const status = getStageStatus(stageDef.key)
          const isRunning = status === 'running'
          const isComplete = status === 'complete'
          const isError = status === 'error'
          const stageData = stages.find(s => s.stageKey === stageDef.key)

          return (
            <div
              key={stageDef.key}
              className={`pipeline-row ${status}`}
              id={`pipeline-stage-${stageDef.key}`}
            >
              <div className="pipeline-sym-col font-mono">
                {isComplete && <span className="sym-complete">✓</span>}
                {isError   && <span className="sym-error">✕</span>}
                {isRunning && <span className="sym-running">◉</span>}
                {!isComplete && !isError && !isRunning && <span className="sym-pending">○</span>}
              </div>

              <div className="pipeline-label-col">
                <span className="pipeline-stage-name">{stageDef.label}</span>
                {stageData?.data?.fileCount !== undefined && (
                  <span className="pipeline-count-tag font-mono">{stageData.data.fileCount} file(s)</span>
                )}
                {stageData?.data?.eventCount !== undefined && (
                  <span className="pipeline-count-tag font-mono">{stageData.data.eventCount} events</span>
                )}
                {stageData?.data?.threatCount !== undefined && (
                  <span className="pipeline-count-tag font-mono">{stageData.data.threatCount} patterns</span>
                )}
                {stageData?.data?.findingCount !== undefined && (
                  <span className="pipeline-count-tag font-mono">{stageData.data.findingCount} findings</span>
                )}
                {stageData?.data?.recCount !== undefined && (
                  <span className="pipeline-count-tag font-mono">{stageData.data.recCount} directives</span>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {hasError && (
        <div className="pipeline-error-box animate-fade-in">
          <AlertCircle size={13} />
          <span>Analysis halted at stage: {errorStage?.stageKey}. {errorStage?.data?.error}</span>
        </div>
      )}

      <div ref={bottomRef} />
    </div>
  )
}
