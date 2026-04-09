'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { startScan } from '@/lib/api'

const CHECKS = [
  { id: 'cors',             label: 'CORS',                 category: 'Access Control' },
  { id: 'forced-browsing',  label: 'Forced browsing',      category: 'Access Control' },
  { id: 'idor',             label: 'IDOR',                 category: 'Access Control' },
  { id: 'http-method-abuse',label: 'HTTP method abuse',    category: 'Access Control' },
  { id: 'sqli',             label: 'SQL injection',        category: 'Injection' },
  { id: 'xss',              label: 'XSS',                  category: 'Injection' },
  { id: 'ssti',             label: 'SSTI',                 category: 'Injection' },
  { id: 'os-command',       label: 'OS command injection', category: 'Injection' },
  { id: 'cookies',          label: 'Cookies & headers',    category: 'Auth' },
  { id: 'jwt',              label: 'JWT',                  category: 'Auth' },
  { id: 'csrf',             label: 'CSRF',                 category: 'Auth' },
  { id: 'ssrf',             label: 'SSRF',                 category: 'Auth' },
  { id: 'file-upload',      label: 'File upload',          category: 'Injection' },
  { id: 'xxe',              label: 'XXE injection',        category: 'Injection' },
]

export default function ScanForm() {
  const [url, setUrl]           = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [mode, setMode]         = useState<'all' | 'custom'>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const router                  = useRouter()

  const toggleCheck = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleScan = async () => {
    setError('')
    if (!url.trim()) return setError('Please enter a URL')
    const target = url.startsWith('http') ? url : `https://${url}`
    try { new URL(target) } catch { return setError('Please enter a valid URL') }
    if (mode === 'custom' && selected.size === 0)
      return setError('Select at least one check')

    setLoading(true)
    try {
      const checks = mode === 'all' ? ['all'] : [...selected]
      const { scanId } = await startScan(target, checks)
      router.push(`/scan/${scanId}`)
    } catch (err: any) {
      setError(err.message)
      setLoading(false)
    }
  }

  return (
    <div className="w-full max-w-2xl space-y-4">
      {/* URL input */}
      <div className="flex gap-2">
        <input
          type="text"
          value={url}
          onChange={e => { setUrl(e.target.value); setError('') }}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="https://example.com"
          disabled={loading}
          className="flex-1 px-4 py-3 rounded-xl border border-gray-300 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
        />
        <button
          onClick={handleScan}
          disabled={loading}
          className="px-6 py-3 bg-blue-600 text-white text-sm font-medium rounded-xl hover:bg-blue-700 active:scale-95 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {loading ? (
            <>
              <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Starting...
            </>
          ) : 'Scan'}
        </button>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('all')}
          className={`px-4 py-2 rounded-lg text-xs font-medium border transition-all ${
            mode === 'all'
              ? 'bg-blue-600 text-white border-blue-600'
              : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
          }`}
        >
          Scan all checks
        </button>
        <button
          onClick={() => setMode('custom')}
          className={`px-4 py-2 rounded-lg text-xs font-medium border transition-all ${
            mode === 'custom'
              ? 'bg-blue-600 text-white border-blue-600'
              : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
          }`}
        >
          Choose checks
        </button>
      </div>

      {/* Check selector */}
      {mode === 'custom' && (
        <div className="grid grid-cols-2 gap-2">
          {CHECKS.map(c => {
            const active = selected.has(c.id)
            return (
              <button
                key={c.id}
                onClick={() => toggleCheck(c.id)}
                className={`flex items-center gap-2 px-3 py-2.5 rounded-xl border text-left text-xs font-medium transition-all ${
                  active
                    ? 'bg-blue-50 border-blue-400 text-blue-700'
                    : 'bg-white border-gray-200 text-gray-600 hover:border-gray-400'
                }`}
              >
                <span className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 ${
                  active ? 'bg-blue-600 border-blue-600' : 'border-gray-300'
                }`}>
                  {active && <span className="text-white text-xs">✓</span>}
                </span>
                <span>{c.label}</span>
                <span className={`ml-auto text-xs px-1.5 py-0.5 rounded ${
                  active ? 'bg-blue-100 text-blue-600' : 'bg-gray-100 text-gray-400'
                }`}>
                  {c.category}
                </span>
              </button>
            )
          })}
        </div>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  )
} 