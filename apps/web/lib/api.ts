import { Scan } from '@/types/scan'

const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000'

export async function startScan(url: string, checks: string[]): Promise<{ scanId: string }> {
  const res = await fetch(`${BASE}/api/scan`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url, checks }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.error || 'Failed to start scan')
  }
  return res.json()
}

export async function getScan(scanId: string): Promise<Scan> {
  const res = await fetch(`${BASE}/api/scan/${scanId}`, {
    cache: 'no-store',
  })
  if (!res.ok) throw new Error('Scan not found')
  return res.json()
}