export type Severity   = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type ScanStatus = 'QUEUED' | 'RUNNING' | 'DONE' | 'FAILED'

export interface Finding {
  id:          string
  category:    string
  checkName:   string
  severity:    Severity
  title:       string
  description: string
  evidence?:   string
  remediation: string
}

export interface Scan {
  id:          string
  url:         string
  status:      ScanStatus
  score?:      number
  startedAt:   string
  finishedAt?: string
  findings:    Finding[]
}