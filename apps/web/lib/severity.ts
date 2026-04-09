import { Severity } from '@/types/scan'

export const SEVERITY_CONFIG: Record<Severity, {
  label:  string
  bg:     string
  text:   string
  border: string
  dot:    string
}> = {
  CRITICAL: { label: 'Critical', bg: 'bg-red-50',    text: 'text-red-700',    border: 'border-red-200',    dot: 'bg-red-500'    },
  HIGH:     { label: 'High',     bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', dot: 'bg-orange-500' },
  MEDIUM:   { label: 'Medium',   bg: 'bg-yellow-50', text: 'text-yellow-700', border: 'border-yellow-200', dot: 'bg-yellow-500' },
  LOW:      { label: 'Low',      bg: 'bg-blue-50',   text: 'text-blue-700',   border: 'border-blue-200',   dot: 'bg-blue-500'   },
  INFO:     { label: 'Info',     bg: 'bg-gray-50',   text: 'text-gray-600',   border: 'border-gray-200',   dot: 'bg-gray-400'   },
}

export function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-600'
  if (score >= 60) return 'text-yellow-600'
  if (score >= 40) return 'text-orange-600'
  return 'text-red-600'
}

export function scoreLabel(score: number): string {
  if (score >= 80) return 'Low Risk'
  if (score >= 60) return 'Moderate Risk'
  if (score >= 40) return 'High Risk'
  return 'Critical Risk'
}

export function scoreRingColor(score: number): string {
  if (score >= 80) return '#16a34a'
  if (score >= 60) return '#ca8a04'
  if (score >= 40) return '#ea580c'
  return '#dc2626'
}