import { Finding, ScanResult }     from '@vuln-scanner/shared-types'
import { crawl, DiscoveredEndpoint } from './utils/crawler'

// ── Checks ────────────────────────────────────────────────────────────────
import { corsCheck }           from './checks/broken-access-control/cors.check'
import { forcedBrowsingCheck } from './checks/broken-access-control/forced-browsing.check'
import { httpMethodAbuseCheck } from './checks/broken-access-control/http-method-abuse.check'
import { idorCheck }           from './checks/broken-access-control/idor.check'
import { sqliCheck }           from './checks/injection/sqli.check'
import { xssCheck }            from './checks/injection/xss.check'
import { sstiCheck }           from './checks/injection/ssti.check'
import { osCommandCheck }      from './checks/injection/os-command.check'
import { cookieCheck }         from './checks/auth/cookie.check'
import { jwtCheck }            from './checks/auth/jwt.check'
import { csrfCheck }           from './checks/auth/csrf.check'
import { ssrfCheck }           from './checks/auth/ssrf.check'
import { fileUploadCheck }     from './checks/injection/file-upload.check'
import { xxeCheck }            from './checks/injection/xxe.check'

const SEVERITY_WEIGHTS: Record<string, number> = {
  CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 0,
}

// ── Check registry ────────────────────────────────────────────────────────
// type: 'site'     = runs once against the root URL
// type: 'endpoint' = runs against every discovered endpoint
export const CHECK_REGISTRY = [
  // Site-wide checks (run once)
  { id: 'cors',              label: 'CORS misconfiguration',          category: 'broken-access-control', type: 'site',     fn: corsCheck            },
  { id: 'forced-browsing',   label: 'Forced browsing',                category: 'broken-access-control', type: 'site',     fn: forcedBrowsingCheck  },
  { id: 'http-method-abuse', label: 'HTTP method abuse',              category: 'broken-access-control', type: 'site',     fn: httpMethodAbuseCheck },
  { id: 'cookies',           label: 'Cookie & security headers',      category: 'auth',                  type: 'site',     fn: cookieCheck          },
  { id: 'jwt',               label: 'JWT vulnerabilities',            category: 'auth',                  type: 'site',     fn: jwtCheck             },
  { id: 'csrf',              label: 'CSRF protection',                category: 'auth',                  type: 'site',     fn: csrfCheck            },
  { id: 'ssrf',              label: 'SSRF detection',                 category: 'auth',                  type: 'site',     fn: ssrfCheck            },

  // Per-endpoint checks (run against every crawled URL)
  { id: 'sqli',              label: 'SQL injection',                  category: 'injection',             type: 'endpoint', fn: sqliCheck            },
  { id: 'xss',               label: 'Cross-site scripting (XSS)',     category: 'injection',             type: 'endpoint', fn: xssCheck             },
  { id: 'ssti',              label: 'Server-side template injection', category: 'injection',             type: 'endpoint', fn: sstiCheck            },
  { id: 'os-command',        label: 'OS command injection',           category: 'injection',             type: 'endpoint', fn: osCommandCheck       },
  { id: 'idor',              label: 'IDOR probing',                   category: 'broken-access-control', type: 'endpoint', fn: idorCheck            },
  { id: 'file-upload',       label: 'File upload vulnerability',      category: 'injection',             type: 'endpoint', fn: fileUploadCheck      },
  { id: 'xxe',               label: 'XXE injection',                  category: 'injection',             type: 'endpoint', fn: xxeCheck             },
] as const

type CheckEntry = typeof CHECK_REGISTRY[number]

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>()
  return findings.filter(f => {
    const key = `${f.checkName}:${f.title}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function calculateScore(findings: Finding[]): number {
  const penalty = findings.reduce(
    (acc, f) => acc + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0
  )
  return Math.max(0, 100 - penalty)
}

function shouldRun(check: CheckEntry, selected: string[]): boolean {
  if (selected.includes('all')) return true
  return selected.includes(check.id) || selected.includes(check.category)
}

async function runCheck(
  fn: (url: string) => Promise<Finding[]>,
  url: string,
  label: string,
): Promise<Finding[]> {
  try {
    return await fn(url)
  } catch (err: any) {
    console.error(`[orchestrator] Check "${label}" failed on ${url}:`, err.message)
    return []
  }
}

export async function runScan(url: string, checks: string[] = ['all']): Promise<ScanResult> {
  console.log(`[scanner] Starting scan for ${url} | checks: ${checks.join(', ')}`)
  try { new URL(url) } catch { throw new Error(`Invalid URL: ${url}`) }

  const selectedChecks = CHECK_REGISTRY.filter(c => shouldRun(c, checks))
  const siteChecks     = selectedChecks.filter(c => c.type === 'site')
  const endpointChecks = selectedChecks.filter(c => c.type === 'endpoint')

  console.log(`[scanner] Site checks: ${siteChecks.map(c => c.id).join(', ') || 'none'}`)
  console.log(`[scanner] Endpoint checks: ${endpointChecks.map(c => c.id).join(', ') || 'none'}`)

  // ── Phase 1: site-wide checks (run once against root URL) ────────────────
  const siteResults = await Promise.allSettled(
    siteChecks.map(c => runCheck(c.fn, url, c.id))
  )
  const siteFindings = siteResults.flatMap(r =>
    r.status === 'fulfilled' ? r.value : []
  )

  // ── Phase 2: crawl (only if endpoint checks are selected) ────────────────
  let endpointFindings: Finding[] = []

  if (endpointChecks.length > 0) {
    const endpoints = await crawl(url, 40, 3)

    const BATCH_SIZE = 5
    const allEndpointResults: Finding[] = []

    for (let i = 0; i < endpoints.length; i += BATCH_SIZE) {
      const batch = endpoints.slice(i, i + BATCH_SIZE)

      const batchResults = await Promise.allSettled(
        batch.flatMap((ep: DiscoveredEndpoint) =>
          endpointChecks.map(c => runCheck(c.fn, ep.url, c.id))
        )
      )

      allEndpointResults.push(
        ...batchResults.flatMap(r => r.status === 'fulfilled' ? r.value : [])
      )
    }

    endpointFindings = allEndpointResults
  }

  const allFindings = deduplicateFindings([...siteFindings, ...endpointFindings])
  const score       = calculateScore(allFindings)

  console.log(`[scanner] Done. ${allFindings.length} findings, score: ${score}`)
  return { findings: allFindings, score }
}