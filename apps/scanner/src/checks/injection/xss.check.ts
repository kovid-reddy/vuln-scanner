import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'injection'
const DEBUG = false   // set false in production

function log(...args: any[]) {
  if (DEBUG) console.log('[xss]', ...args)
}

const PAYLOADS = [
  { payload: '<script>alert(1)</script>',        marker: 'alert(1)'           },
  { payload: '"><script>alert(1)</script>',       marker: 'alert(1)'           },
  { payload: '<img src=x onerror=alert(1)>',      marker: 'onerror=alert'      },
  { payload: '"><img src=x onerror=alert(1)>',    marker: 'onerror=alert'      },
  { payload: '<svg onload=alert(1)>',             marker: 'onload=alert'       },
  { payload: '" onmouseover="alert(1)',            marker: 'onmouseover='       },
  { payload: "' onmouseover='alert(1)",           marker: 'onmouseover='       },
  { payload: '<body onload=alert(1)>',            marker: 'onload=alert'       },
  // Encoded bypasses
  { payload: '%3Cscript%3Ealert(1)%3C/script%3E', marker: 'alert(1)'          },
  { payload: '<ScRiPt>alert(1)</ScRiPt>',         marker: 'alert(1)'          },
]

function analyzeCSP(headers: Record<string, any>): {
  hasCSP:     boolean
  bypassable: boolean
  value:      string
} {
  const csp = String(headers['content-security-policy'] ?? '')
  if (!csp) return { hasCSP: false, bypassable: true, value: '' }

  const bypassable =
    csp.includes("'unsafe-inline'") ||
    csp.includes('*') ||
    !csp.includes('script-src')

  return { hasCSP: true, bypassable, value: csp }
}

function buildGetVariants(url: string, payload: string): { testUrl: string; param: string }[] {
  const parsed  = new URL(url)
  const results: { testUrl: string; param: string }[] = []

  // Inject into every existing param
  for (const key of parsed.searchParams.keys()) {
    const modified = new URL(url)
    modified.searchParams.set(key, payload)
    results.push({ testUrl: modified.toString(), param: key })
  }

  // Also try common params if none exist
  if (results.length === 0) {
    for (const param of ['q', 'search', 'query', 's', 'input', 'name', 'keyword', 'term', 'text']) {
      const modified = new URL(url)
      modified.searchParams.set(param, payload)
      results.push({ testUrl: modified.toString(), param })
    }
  }

  return results
}

// Checks if payload is reflected — handles both raw and HTML-entity-encoded forms
function isReflected(body: string, payload: string, marker: string): boolean {
  // Direct reflection
  if (body.includes(marker)) return true

  // HTML entity encoded reflection (browser would still render it)
  const encoded = marker
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')

  if (body.includes(encoded)) {
    log(`Found HTML-encoded reflection: ${encoded}`)
    return false  // encoded = escaped = NOT vulnerable
  }

  // Partial reflection — just the JS part without tags
  const jsOnly = marker.replace(/<[^>]+>/g, '').trim()
  if (jsOnly.length > 4 && body.includes(jsOnly)) return true

  return false
}

export async function xssCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported  = new Set<string>()

  // ── Baseline + CSP check ─────────────────────────────────────────────────
  let csp = { hasCSP: false, bypassable: true, value: '' }
  try {
    const baseline = await http.get(url, { timeout: 10000 })
    csp = analyzeCSP(baseline.headers as Record<string, any>)
    log(`CSP: hasCSP=${csp.hasCSP}, bypassable=${csp.bypassable}`)
    log(`Status: ${baseline.status}, body length: ${String(baseline.data).length}`)

    if (!csp.hasCSP) {
      findings.push({
        category:    CAT,
        checkName:   'xss-no-csp',
        severity:    'MEDIUM',
        title:       'No Content-Security-Policy header',
        description: 'The server does not send a CSP header. Without CSP, injected scripts execute freely in victims\' browsers.',
        evidence:    `URL: ${url}\nContent-Security-Policy: absent`,
        remediation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'\nThis blocks execution of injected scripts.",
      })
    } else if (csp.bypassable) {
      findings.push({
        category:    CAT,
        checkName:   'xss-weak-csp',
        severity:    'LOW',
        title:       'Content-Security-Policy is weak or bypassable',
        description: "CSP is present but allows 'unsafe-inline', wildcards, or lacks script-src.",
        evidence:    `Content-Security-Policy: ${csp.value}`,
        remediation: "Remove 'unsafe-inline' and wildcard sources. Use nonces or hashes for inline scripts.",
      })
    }

    // Check X-Content-Type-Options
    const xcto = String(baseline.headers['x-content-type-options'] ?? '')
    if (!xcto.includes('nosniff')) {
      findings.push({
        category:    CAT,
        checkName:   'xss-missing-nosniff',
        severity:    'LOW',
        title:       'Missing X-Content-Type-Options: nosniff',
        description: 'Without nosniff, browsers may MIME-sniff responses and execute uploaded files as scripts.',
        evidence:    `X-Content-Type-Options: ${xcto || 'absent'}`,
        remediation: 'Add header: X-Content-Type-Options: nosniff',
      })
    }

    // Check X-XSS-Protection (legacy but still useful signal)
    const xxp = String(baseline.headers['x-xss-protection'] ?? '')
    if (!xxp) {
      log('X-XSS-Protection header absent')
    }

  } catch (err: any) {
    log(`Baseline request failed: ${err.message}`)
  }

  // ── Reflected XSS — GET params ──────────────────────────────────────────
  for (const { payload, marker } of PAYLOADS) {
    const variants = buildGetVariants(url, payload)

    for (const { testUrl, param } of variants) {
      const key = `reflected-get-${param}`
      if (reported.has(key)) continue

      try {
        const res  = await http.get(testUrl, { timeout: 10000 })
        const body = String(res.data)

        log(`Testing param="${param}" payload="${payload.slice(0, 30)}" status=${res.status} bodyLen=${body.length}`)

        // Log a snippet to see what the server actually returns
        if (DEBUG) {
          const idx = body.toLowerCase().indexOf('alert')
          if (idx !== -1) {
            log(`Found 'alert' in response at pos ${idx}: ...${body.slice(Math.max(0, idx - 30), idx + 60)}...`)
          }
        }

        if (isReflected(body, payload, marker)) {
          reported.add(key)
          log(`FOUND reflected XSS on param "${param}" with payload "${payload}"`)

          findings.push({
            category:    CAT,
            checkName:   'xss-reflected-get',
            severity:    csp.bypassable ? 'HIGH' : 'MEDIUM',
            title:       `Reflected XSS — GET param "${param}"`,
            description: `The "${param}" parameter reflects user input directly into the HTML response without escaping. An attacker can craft a malicious URL that executes JavaScript in the victim's browser.`,
            evidence: [
              `URL: ${testUrl}`,
              `Payload: ${payload}`,
              `Marker reflected: "${marker}"`,
              `CSP: ${csp.hasCSP ? csp.value.slice(0, 80) : 'absent'}`,
            ].join('\n'),
            remediation: 'HTML-encode all user-controlled output before rendering. Use htmlspecialchars() in PHP, template engine auto-escaping in others. Add a strict CSP.',
          })
          break
        }
      } catch (err: any) {
        log(`Request failed for param="${param}": ${err.message}`)
      }
    }
  }

  log(`Done. Total findings: ${findings.length}`)
  return findings
}
