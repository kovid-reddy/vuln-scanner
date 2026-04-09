'use client'
import { useState } from 'react'
import { Finding } from '@/types/scan'
import SeverityBadge from './SeverityBadge'

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const normalizedSeverity = finding.severity?.toUpperCase() as Severity
  // then pass normalizedSeverity to SeverityBadge
  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden bg-white">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
      >
        <SeverityBadge severity={normalizedSeverity} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-gray-900">{finding.title}</p>
          <p className="text-xs text-gray-500 mt-0.5">{finding.checkName}</p>
        </div>
        <span className="text-gray-400 text-xs mt-1 flex-shrink-0">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="border-t border-gray-100 px-4 pb-4 pt-3 space-y-3">
          <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Description</p>
            <p className="text-sm text-gray-700">{finding.description}</p>
          </div>
          {finding.evidence && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Evidence</p>
              <pre className="text-xs bg-gray-50 border border-gray-200 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap text-gray-700">
                {finding.evidence}
              </pre>
            </div>
          )}
          <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Remediation</p>
            <p className="text-sm text-green-700 bg-green-50 border border-green-200 rounded-lg p-3">
              {finding.remediation}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}