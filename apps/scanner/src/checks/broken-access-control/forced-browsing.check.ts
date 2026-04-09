import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'
import { SENSITIVE_PATHS } from './wordlist'

const CAT = 'broken-access-control'

// Status codes that mean the path actually exists and is accessible
const EXPOSED_STATUSES = [200, 201, 301, 302, 307, 308]
const AUTH_STATUSES    = [401, 403]   // exists but protected — good

interface PathResult {
  path:       string
  status:     number
  bodySnippet: string
}

function getBaseUrl(url: string): string {
  const parsed = new URL(url)
  return `${parsed.protocol}//${parsed.host}`
}

function extractSnippet(body: string): string {
  // Grab first 200 chars, strip HTML tags
  return body.replace(/<[^>]+>/g, '').trim().slice(0, 200)
}

function severityForPath(path: string, status: number): Finding['severity'] {
  const critical = ['/.env', '/.git/config', '/backup.sql', '/db.sql',
                    '/database.sql', '/dump.sql', '/phpinfo.php', '/actuator/env']
  const high     = ['/admin', '/wp-admin', '/phpmyadmin', '/config.json',
                    '/swagger.json', '/openapi.json', '/api/admin']

  if (critical.some(p => path.startsWith(p))) return 'CRITICAL'
  if (high.some(p => path.startsWith(p)))     return 'HIGH'
  if (status === 200)                          return 'MEDIUM'
  return 'LOW'
}

export async function forcedBrowsingCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const base = getBaseUrl(url)
  const exposed: PathResult[] = []

  // Run in batches of 10 to avoid hammering the server
  const BATCH = 10
  for (let i = 0; i < SENSITIVE_PATHS.length; i += BATCH) {
    const batch = SENSITIVE_PATHS.slice(i, i + BATCH)

    await Promise.allSettled(
      batch.map(async (path: string) => {
        try {
          const res = await http.get(`${base}${path}`, { timeout: 6000 })

          if (EXPOSED_STATUSES.includes(res.status)) {
            exposed.push({
              path,
              status:      res.status,
              bodySnippet: extractSnippet(String(res.data)),
            })
          }
        } catch {
          // unreachable path — expected, skip
        }
      })
    )
  }

  for (const result of exposed) {
    findings.push({
      category:    CAT,
      checkName:   'forced-browsing',
      severity:    severityForPath(result.path, result.status),
      title:       `Sensitive path exposed: ${result.path}`,
      description: `The path ${result.path} is publicly accessible (HTTP ${result.status}).`,
      evidence:    `GET ${base}${result.path} → ${result.status}\nResponse: ${result.bodySnippet}`,
      remediation:
        'Restrict access to sensitive paths via server config. Remove backup files and dev artifacts from production. Protect admin routes with authentication.',
    })
  }

  return findings
}
