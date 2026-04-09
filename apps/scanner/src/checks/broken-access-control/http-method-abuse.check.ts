import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'broken-access-control'

const DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'] as const

// Status codes that indicate the method was actually accepted
const ACCEPTED = [200, 201, 204, 301, 302, 307]

// Status codes that mean the server rejected it properly
const REJECTED = [405, 501, 400, 403, 401]

function severityForMethod(method: string, status: number): Finding['severity'] {
  if (['DELETE', 'PUT'].includes(method) && ACCEPTED.includes(status)) return 'CRITICAL'
  if (method === 'TRACE' && status === 200) return 'MEDIUM'  // XST attack vector
  if (ACCEPTED.includes(status)) return 'HIGH'
  return 'LOW'
}

export async function httpMethodAbuseCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const method of DANGEROUS_METHODS) {
    try {
      const res = await http.request({
        method,
        url,
        data:    method === 'PUT' || method === 'PATCH' ? '{"test":1}' : undefined,
        headers: { 'Content-Type': 'application/json' },
        timeout: 6000,
      })

      if (ACCEPTED.includes(res.status)) {
        findings.push({
          category:    CAT,
          checkName:   'http-method-abuse',
          severity:    severityForMethod(method, res.status),
          title:       `Dangerous HTTP method accepted: ${method}`,
          description: `The server accepted an HTTP ${method} request with status ${res.status}. This method should not be available on this endpoint.`,
          evidence:    `${method} ${url} → HTTP ${res.status}`,
          remediation:
            `Disable the ${method} method on this endpoint unless explicitly required. Configure your web server to return 405 Method Not Allowed for unused HTTP verbs.`,
        })
      } else if (method === 'TRACE' && !REJECTED.includes(res.status)) {
        findings.push({
          category:    CAT,
          checkName:   'http-trace-enabled',
          severity:    'MEDIUM',
          title:       'HTTP TRACE method may be enabled',
          description: `Server returned an unexpected status (${res.status}) for TRACE — may indicate TRACE is partially enabled.`,
          evidence:    `TRACE ${url} → HTTP ${res.status}`,
          remediation: 'Disable TRACE method in your web server configuration. It enables Cross-Site Tracing (XST) attacks.',
        })
      }
    } catch {
      // Method rejected at network level — that's fine
    }
  }

  return findings
}