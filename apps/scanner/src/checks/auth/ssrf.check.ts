import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'auth-failures'
const DEBUG = false
function log(...args: any[]) { if (DEBUG) console.log('[ssrf]', ...args) }

// SSRF probe targets — internal/metadata endpoints
const SSRF_PROBES = [
  // Cloud metadata services
  { url: 'http://169.254.169.254/latest/meta-data/',              label: 'AWS metadata service'      },
  { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', label: 'AWS IAM credentials' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/',   label: 'GCP metadata service'      },
  { url: 'http://169.254.169.254/metadata/v1/',                   label: 'DigitalOcean metadata'     },
  { url: 'http://100.100.100.200/latest/meta-data/',              label: 'Alibaba Cloud metadata'    },
  // Internal services
  { url: 'http://localhost/',                                      label: 'localhost'                },
  { url: 'http://127.0.0.1/',                                     label: '127.0.0.1'                 },
  { url: 'http://0.0.0.0/',                                       label: '0.0.0.0'                   },
  { url: 'http://[::1]/',                                         label: 'IPv6 localhost'            },
  { url: 'http://127.0.0.1:6379/',                                label: 'Redis (6379)'              },
  { url: 'http://127.0.0.1:27017/',                               label: 'MongoDB (27017)'           },
  { url: 'http://127.0.0.1:5432/',                                label: 'PostgreSQL (5432)'         },
]

// URL params commonly used to fetch remote resources
const URL_PARAMS = [
  'url', 'uri', 'src', 'source', 'href', 'link', 'path',
  'redirect', 'next', 'return', 'callback', 'fetch',
  'load', 'file', 'target', 'dest', 'destination',
  'proxy', 'forward', 'download', 'image', 'img',
  'resource', 'endpoint', 'api', 'service',
]

// Indicators that the server fetched our probe URL
const METADATA_INDICATORS = [
  'ami-id', 'instance-id', 'local-ipv4',       // AWS
  'computeMetadata', 'serviceAccounts',          // GCP
  'droplet_id', 'region',                        // DigitalOcean
  'redis_version', 'redis_mode',                 // Redis
  'mongodb', 'wireVersion',                      // MongoDB
]

function buildSSRFVariants(targetUrl: string, ssrfPayload: string): { testUrl: string; param: string }[] {
  const parsed  = new URL(targetUrl)
  const results: { testUrl: string; param: string }[] = []

  // Inject into existing params that look like URLs
  for (const [key, val] of parsed.searchParams.entries()) {
    if (val.startsWith('http') || URL_PARAMS.includes(key.toLowerCase())) {
      const modified = new URL(targetUrl)
      modified.searchParams.set(key, ssrfPayload)
      results.push({ testUrl: modified.toString(), param: key })
    }
  }

  // Try common URL params
  for (const param of URL_PARAMS) {
    if (!parsed.searchParams.has(param)) {
      const modified = new URL(targetUrl)
      modified.searchParams.set(param, ssrfPayload)
      results.push({ testUrl: modified.toString(), param })
    }
  }

  return results.slice(0, 10)  // cap at 10 variants per probe
}

function containsMetadataIndicator(body: string): string | null {
  const lower = body.toLowerCase()
  return METADATA_INDICATORS.find(ind => lower.includes(ind.toLowerCase())) ?? null
}

export async function ssrfCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  // ── 1. Parameter-based SSRF ─────────────────────────────────────────────
  for (const probe of SSRF_PROBES.slice(0, 6)) {  // test top 6 probes
    const variants = buildSSRFVariants(url, probe.url)

    for (const { testUrl, param } of variants.slice(0, 3)) {
      const key = `ssrf-${param}-${probe.label}`
      if (reported.has(key)) continue

      try {
        const res  = await http.get(testUrl, { timeout: 8000 })
        const body = String(res.data)
        const hit  = containsMetadataIndicator(body)

        log(`param="${param}" probe="${probe.label}" status=${res.status} hit=${hit}`)

        if (hit) {
          reported.add(key)
          findings.push({
            category:    CAT,
            checkName:   'ssrf-internal-fetch',
            severity:    'CRITICAL',
            title:       `SSRF — server fetched internal resource via param "${param}"`,
            description: `The server fetched the ${probe.label} URL when the "${param}" parameter was set to an internal address. This enables attackers to probe internal infrastructure, steal cloud credentials, and pivot to internal services.`,
            evidence: [
              `Probe URL: ${probe.url}`,
              `Test URL: ${testUrl}`,
              `Metadata indicator found: "${hit}"`,
              `Response snippet: ${body.slice(0, 300)}`,
            ].join('\n'),
            remediation: 'Validate and sanitize all URL parameters. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use an allowlist of permitted external domains. Disable unnecessary outbound connections.',
          })
          break
        }

        // Even if no metadata found, getting a 200 on a localhost probe is suspicious
        if (
          res.status === 200 &&
          (probe.label.includes('localhost') || probe.label.includes('127')) &&
          body.length > 100
        ) {
          reported.add(key)
          findings.push({
            category:    CAT,
            checkName:   'ssrf-localhost-response',
            severity:    'HIGH',
            title:       `Possible SSRF — server returned content for localhost probe via "${param}"`,
            description: `The server returned a non-empty 200 response when "${param}" was set to ${probe.url}. This may indicate the server is fetching the URL server-side.`,
            evidence: [
              `Probe: ${probe.url}`,
              `Test URL: ${testUrl}`,
              `Response: ${res.status} (${body.length} bytes)`,
              `Snippet: ${body.slice(0, 200)}`,
            ].join('\n'),
            remediation: 'Block server-side requests to loopback addresses. Validate URL parameters against an allowlist of permitted destinations.',
          })
          break
        }
      } catch { /* skip — connection refused is expected for closed ports */ }
    }

    if (findings.length >= 2) break  // enough evidence, stop probing
  }

  // ── 2. Open redirect as SSRF vector ────────────────────────────────────
  const parsed = new URL(url)
  for (const param of ['redirect', 'next', 'return', 'url', 'callback']) {
    if (parsed.searchParams.has(param)) {
      const modified = new URL(url)
      modified.searchParams.set(param, 'http://169.254.169.254/')

      try {
        const res = await http.get(modified.toString(), {
          timeout:      8000,
          maxRedirects: 0,  // don't follow — we want to see if it redirects to metadata
        })

        const location = String(res.headers['location'] ?? '')
        if (location.includes('169.254.169.254') || location.includes('metadata')) {
          findings.push({
            category:    CAT,
            checkName:   'ssrf-open-redirect',
            severity:    'HIGH',
            title:       `Open redirect to internal IP via param "${param}"`,
            description: `The "${param}" parameter redirected to an internal/metadata address. Combined with other vulnerabilities, this can enable SSRF.`,
            evidence:    `Redirect URL: ${modified.toString()}\nLocation header: ${location}`,
            remediation: 'Validate redirect destinations against an allowlist. Never redirect to user-supplied arbitrary URLs.',
          })
        }
      } catch { /* skip */ }
    }
  }

  return findings
}
