import ScanForm from '@/components/ScanForm'

export default function Home() {
  return (
    <main className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4">
      <div className="text-center mb-10 space-y-3">
        <div className="inline-flex items-center gap-2 bg-blue-50 border border-blue-200 text-blue-700 text-xs font-medium px-3 py-1.5 rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
          OWASP Top 10 Scanner
        </div>
        <h1 className="text-4xl font-bold text-gray-900 tracking-tight">WebScore</h1>
        <p className="text-gray-500 text-base max-w-md">
          Paste any URL and get an instant security rating based on real vulnerability checks.
        </p>
      </div>

      <ScanForm />

      <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl w-full">
        {[
          { label: 'CORS misconfig',    icon: '🔀' },
          { label: 'Forced browsing',   icon: '📂' },
          { label: 'IDOR probing',      icon: '🔢' },
          { label: 'HTTP method abuse', icon: '⚡' },
        ].map(c => (
          <div key={c.label} className="flex items-center gap-2 bg-white border border-gray-200 rounded-xl px-3 py-2.5 text-xs text-gray-600">
            <span>{c.icon}</span>
            {c.label}
          </div>
        ))}
      </div>

      <p className="mt-12 text-xs text-gray-400 text-center max-w-sm">
        Only scan websites you own or have explicit permission to test.
      </p>
    </main>
  )
}