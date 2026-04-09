export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type ScanStatus = 'QUEUED' | 'RUNNING' | 'DONE' | 'FAILED'

export interface Finding {
  category:    string
  checkName:   string
  severity:    Severity
  title:       string
  description: string
  evidence?:   string
  remediation: string
}

export interface ScanResult {
  findings: Finding[]
  score:    number
}

export interface ScanResponse {
  scanId:   string
  status:   ScanStatus
  score?:   number
  url:      string
  findings?: Finding[]
}
