import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'cryptographic-failures'

interface ParsedCookie {
  name:       string
  value:      string
  flags:      string[]
  raw:        string
}

function parseCookies(headers: Record<string, any>): ParsedCookie[] {
  const raw = headers['set-cookie']
  if (!raw) return []

  const cookieLines: string[] = Array.isArray(raw) ? raw : [raw]

  return cookieLines.map(line => {
    const parts = line.split(';').map((p: string) => p.trim())
    const [nameValue, ...flags] = parts
    const [name, ...valueParts] = nameValue.split('=')
    return {
      name:  name?.trim() ?? '',
      value: valueParts.join('='),
      flags: flags.map((f: string) => f.toLowerCase()),
      raw:   line,
    }
  })
}

function isSessionCookie(name: string): boolean {
  const sessionNames = [
    'session', 'sess', 'sid', 'sessionid', 'session_id',
    'phpsessid', 'jsessionid', 'asp.net_sessionid',
    'connect.sid', 'auth', 'token', 'jwt', 'access_token',
    'remember_me', 'remember_token',
  ]
  return sessionNames.some(s => name.toLowerCase().includes(s))
}

function hasFlag(cookie: ParsedCookie, flag: string): boolean {
  return cookie.flags.some(f => f.startsWith(flag.toLowerCase()))
}

function getSameSiteValue(cookie: ParsedCookie): string {
  const flag = cookie.flags.find(f => f.startsWith('samesite='))
  return flag ? flag.split('=')[1] ?? '' : ''
}

export async function cookieCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []

  let headers: Record<string, any> = {}
  try {
    const res = await http.get(url, { timeout: 10000 })
    headers = res.headers as Record<string, any>
  } catch (err: any) {
    return [{
      category:    CAT,
      checkName:   'cookie-check-error',
      severity:    'INFO',
      title:       'Cookie check could not complete',
      description: `Could not reach target: ${err.message}`,
      remediation: 'Verify the URL is reachable.',
    }]
  }

  const cookies = parseCookies(headers)

  // ── No cookies at all ───────────────────────────────────────────────────
  if (cookies.length === 0) {
    // Not a finding — just means no cookies set on this endpoint
    return findings
  }

  for (const cookie of cookies) {
    const isSession = isSessionCookie(cookie.name)
    const secure    = hasFlag(cookie, 'secure')
    const httpOnly  = hasFlag(cookie, 'httponly')
    const sameSite  = getSameSiteValue(cookie)
    const isHttps   = url.startsWith('https://')

    // ── Missing Secure flag ────────────────────────────────────────────────
    if (!secure && isHttps) {
      findings.push({
        category:    CAT,
        checkName:   'cookie-missing-secure',
        severity:    isSession ? 'HIGH' : 'MEDIUM',
        title:       `Cookie missing Secure flag — "${cookie.name}"`,
        description: `The "${cookie.name}" cookie is set without the Secure flag on an HTTPS site. It can be transmitted over unencrypted HTTP connections, exposing it to interception.`,
        evidence:    `Set-Cookie: ${cookie.raw}`,
        remediation: `Add the Secure flag: Set-Cookie: ${cookie.name}=...; Secure. This ensures the cookie is only sent over HTTPS.`,
      })
    }

    // ── Missing HttpOnly flag ──────────────────────────────────────────────
    if (!httpOnly && isSession) {
      findings.push({
        category:    CAT,
        checkName:   'cookie-missing-httponly',
        severity:    'HIGH',
        title:       `Session cookie missing HttpOnly flag — "${cookie.name}"`,
        description: `The session cookie "${cookie.name}" is accessible via JavaScript. An XSS vulnerability on this site would allow an attacker to steal this cookie.`,
        evidence:    `Set-Cookie: ${cookie.raw}`,
        remediation: `Add HttpOnly flag: Set-Cookie: ${cookie.name}=...; HttpOnly. This prevents JavaScript from accessing the cookie.`,
      })
    }

    // ── Missing or weak SameSite ───────────────────────────────────────────
    if (!sameSite && isSession) {
      findings.push({
        category:    CAT,
        checkName:   'cookie-missing-samesite',
        severity:    'MEDIUM',
        title:       `Session cookie missing SameSite attribute — "${cookie.name}"`,
        description: `The session cookie "${cookie.name}" has no SameSite attribute, making it vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
        evidence:    `Set-Cookie: ${cookie.raw}`,
        remediation: `Add SameSite=Strict or SameSite=Lax: Set-Cookie: ${cookie.name}=...; SameSite=Lax. This prevents the cookie from being sent in cross-site requests.`,
      })
    } else if (sameSite === 'none' && !secure) {
      findings.push({
        category:    CAT,
        checkName:   'cookie-samesite-none-no-secure',
        severity:    'MEDIUM',
        title:       `Cookie SameSite=None without Secure — "${cookie.name}"`,
        description: `SameSite=None requires the Secure flag per the spec. Without it, modern browsers will reject the cookie entirely.`,
        evidence:    `Set-Cookie: ${cookie.raw}`,
        remediation: 'Use SameSite=None only with the Secure flag. Consider if SameSite=None is actually required.',
      })
    }

    // ── Session cookie without expiry (check if persistent) ───────────────
    const hasExpiry = hasFlag(cookie, 'expires') || hasFlag(cookie, 'max-age')
    if (isSession && !hasExpiry) {
      // Session cookies without expiry are actually fine (expire on browser close)
      // Only flag if value looks like a long-lived token
      if (cookie.value.length > 40) {
        findings.push({
          category:    CAT,
          checkName:   'cookie-no-expiry',
          severity:    'LOW',
          title:       `Long-lived session cookie with no expiry — "${cookie.name}"`,
          description: `The "${cookie.name}" cookie appears to contain a long token but has no Max-Age or Expires attribute. If the session is not invalidated server-side, it could be used indefinitely.`,
          evidence:    `Set-Cookie: ${cookie.raw.slice(0, 100)}...`,
          remediation: 'Set appropriate expiry on session cookies. Implement server-side session invalidation on logout.',
        })
      }
    }
  }

  // ── Security headers (run once, not per-cookie) ────────────────────────

  // HSTS
  const hsts = String(headers['strict-transport-security'] ?? '')
  if (!hsts && url.startsWith('https://')) {
    findings.push({
      category:    'cryptographic-failures',
      checkName:   'missing-hsts',
      severity:    'MEDIUM',
      title:       'Missing Strict-Transport-Security (HSTS) header',
      description: 'Without HSTS, browsers may connect over HTTP first, enabling SSL stripping attacks.',
      evidence:    'Strict-Transport-Security: absent',
      remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    })
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/)
    const maxAge      = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0
    if (maxAge < 15552000) {  // less than 180 days
      findings.push({
        category:    'cryptographic-failures',
        checkName:   'weak-hsts',
        severity:    'LOW',
        title:       'HSTS max-age is too short',
        description: `HSTS max-age is ${maxAge}s (${Math.floor(maxAge / 86400)} days). Recommended minimum is 180 days (15552000s).`,
        evidence:    `Strict-Transport-Security: ${hsts}`,
        remediation: 'Set max-age to at least 31536000 (1 year). Add includeSubDomains and preload.',
      })
    }
  }

  // X-Frame-Options
  const xfo = String(headers['x-frame-options'] ?? '')
  if (!xfo) {
    findings.push({
      category:    CAT,
      checkName:   'missing-x-frame-options',
      severity:    'MEDIUM',
      title:       'Missing X-Frame-Options header',
      description: 'Without X-Frame-Options, this page can be embedded in iframes on other sites, enabling clickjacking attacks.',
      evidence:    'X-Frame-Options: absent',
      remediation: "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN. Alternatively use CSP: frame-ancestors 'none'.",
    })
  }

  // Referrer-Policy
  const rp = String(headers['referrer-policy'] ?? '')
  if (!rp) {
    findings.push({
      category:    CAT,
      checkName:   'missing-referrer-policy',
      severity:    'LOW',
      title:       'Missing Referrer-Policy header',
      description: 'Without a Referrer-Policy, the browser may send the full URL (including sensitive params) as a Referer header to third parties.',
      evidence:    'Referrer-Policy: absent',
      remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    })
  }

  // Permissions-Policy
  const pp = String(headers['permissions-policy'] ?? '')
  if (!pp) {
    findings.push({
      category:    CAT,
      checkName:   'missing-permissions-policy',
      severity:    'LOW',
      title:       'Missing Permissions-Policy header',
      description: 'Without Permissions-Policy, the page does not restrict browser features like camera, microphone, or geolocation from third-party scripts.',
      evidence:    'Permissions-Policy: absent',
      remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    })
  }

  return findings
}
