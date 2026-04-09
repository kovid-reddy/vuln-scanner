'use client'
import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { getScan } from '@/lib/api'
import { Scan } from '@/types/scan'
import ScoreGauge from '@/components/ScoreGauge'
import FindingCard from '@/components/FindingCard'
import SeverityBadge from '@/components/SeverityBadge'
import Link from 'next/link'

const STATUS_MESSAGES: Record<string, string> = {
  QUEUED:  'Scan queued — starting shortly...',
  RUNNING: 'Scanning for vulnerabilities...',
  DONE:    'Scan complete',
  FAILED:  'Scan failed',
}

export default function ScanPage() {
  const { id }            = useParams<{ id: string }>()
  const [scan, setScan]   = useState<Scan | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    const poll = async () => {
      try {
        const data = await getScan(id)
        setScan(data)
        if (data.status === 'DONE' || data.status === 'FAILED') clearInterval(interval)
      } catch (err: any) {
        setError(err.message)
        clearInterval(interval)
      }
    }
    poll()
    const interval = setInterval(poll, 3000)
    return () => clearInterval(interval)
  }, [id])

  if (error) return (
    <main className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="text-center space-y-3">
        <p className="text-red-600 font-medium">{error}</p>
        <Link href="/" className="text-sm text-blue-600 hover:underline">← Back home</Link>
      </div>
    </main>
  )

  if (!scan) return (
    <main className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="flex items-center gap-3 text-gray-500">
        <span className="w-5 h-5 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
        Loading...
      </div>
    </main>
  )

  const isDone    = scan.status === 'DONE'
  const isRunning = scan.status === 'RUNNING' || scan.status === 'QUEUED'

  const grouped = {
    CRITICAL: scan.findings.filter(f => f.severity?.toUpperCase() === 'CRITICAL'),
    HIGH:     scan.findings.filter(f => f.severity?.toUpperCase() === 'HIGH'),
    MEDIUM:   scan.findings.filter(f => f.severity?.toUpperCase() === 'MEDIUM'),
    LOW:      scan.findings.filter(f => f.severity?.toUpperCase() === 'LOW'),
    INFO:     scan.findings.filter(f => f.severity?.toUpperCase() === 'INFO'),
  }

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `webscore-${scan.id}.json`
    a.click()
  }

  return (
    <main className="min-h-screen bg-gray-50">
      <div className="max-w-3xl mx-auto px-4 py-10 space-y-6">

        <div className="flex items-center justify-between">
          <Link href="/" className="text-sm text-gray-500 hover:text-gray-800 transition-colors">
            ← New scan
          </Link>
          {isDone && (
            <button
              onClick={exportJson}
              className="text-xs text-blue-600 border border-blue-200 bg-blue-50 px-3 py-1.5 rounded-lg hover:bg-blue-100 transition-colors"
            >
              Export JSON
            </button>
          )}
        </div>

        <div className="bg-white border border-gray-200 rounded-2xl p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1 min-w-0">
              <p className="text-xs text-gray-400 font-medium uppercase tracking-wide">Target</p>
              <p className="text-sm font-medium text-gray-800 truncate">{scan.url}</p>
              <div className="flex items-center gap-2 mt-2">
                {isRunning && <span className="w-3 h-3 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />}
                <span className={`text-sm ${scan.status === 'DONE' ? 'text-green-600' : scan.status === 'FAILED' ? 'text-red-600' : 'text-blue-600'}`}>
                  {STATUS_MESSAGES[scan.status]}
                </span>
              </div>
            </div>
            {isDone && scan.score != null && <ScoreGauge score={scan.score} />}
          </div>

          {isDone && scan.findings.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-5 pt-5 border-t border-gray-100">
              {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).map(sev =>
                grouped[sev].length ? <SeverityBadge key={sev} severity={sev} /> : null
              )}
              <span className="text-xs text-gray-400 self-center ml-1">
                {scan.findings.length} finding{scan.findings.length !== 1 ? 's' : ''}
              </span>
            </div>
          )}

          {isDone && scan.findings.length === 0 && (
            <div className="mt-5 pt-5 border-t border-gray-100 text-sm text-green-700 bg-green-50 border border-green-200 rounded-xl px-4 py-3">
              No vulnerabilities detected in this scan.
            </div>
          )}
        </div>

        {isDone && scan.findings.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-medium text-gray-700 px-1">Findings</h2>
            {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).flatMap(sev =>
              grouped[sev].map(f => <FindingCard key={f.id} finding={f} />)
            )}
          </div>
        )}

        {isRunning && (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-16 bg-white border border-gray-200 rounded-xl animate-pulse" />
            ))}
          </div>
        )}

      </div>
    </main>
  )
}