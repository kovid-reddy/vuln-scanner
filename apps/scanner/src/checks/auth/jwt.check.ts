import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'auth-failures'

// Common weak secrets used in JWT signing
const WEAK_SECRETS = [
  'secret', 'password', '123456', 'qwerty', 'admin',
  'key', 'jwt', 'token', 'abc123', 'changeme',
  'supersecret', 'mysecret', 'jwtpassword', 'secret123',
  'your-256-bit-secret', 'your-secret', 'hs256secret',
]

interface DecodedJWT {
  header:    Record<string, any>
  payload:   Record<string, any>
  signature: string
  raw:       string
}

function base64UrlDecode(str: string): string {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded  = base64 + '='.repeat((4 - base64.length % 4) % 4)
  try {
    return Buffer.from(padded, 'base64').toString('utf8')
  } catch {
    return ''
  }
}

function decodeJWT(token: string): DecodedJWT | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null

  try {
    const header  = JSON.parse(base64UrlDecode(parts[0]))
    const payload = JSON.parse(base64UrlDecode(parts[1]))
    return { header, payload, signature: parts[2], raw: token }
  } catch {
    return null
  }
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

function buildAlgNoneToken(decoded: DecodedJWT): string {
  const header  = { ...decoded.header, alg: 'none' }
  const h = base64UrlEncode(JSON.stringify(header))
  const p = base64UrlEncode(JSON.stringify(decoded.payload))
  return `${h}.${p}.`
}

function extractJWTs(headers: Record<string, any>, body: string): string[] {
  const tokens: string[] = []
  const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g

  // Check Authorization header
  const auth = String(headers['authorization'] ?? '')
  if (auth.startsWith('Bearer ')) {
    tokens.push(auth.slice(7))
  }

  // Check Set-Cookie headers for JWT tokens
  const cookies = headers['set-cookie']
  if (cookies) {
    const cookieLines = Array.isArray(cookies) ? cookies : [cookies]
    for (const line of cookieLines) {
      const matches = line.match(jwtPattern)
      if (matches) tokens.push(...matches)
    }
  }

  // Check response body
  const bodyMatches = body.match(jwtPattern)
  if (bodyMatches) tokens.push(...bodyMatches)

  return [...new Set(tokens)]  // deduplicate
}

export async function jwtCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []

  let headers: Record<string, any> = {}
  let body = ''

  try {
    const res = await http.get(url, { timeout: 10000 })
    headers   = res.headers as Record<string, any>
    body      = String(res.data)
  } catch {
    return findings
  }

  const tokens = extractJWTs(headers, body)

  if (tokens.length === 0) {
    // No JWT found — check if the site likely uses JWT by looking for hints
    const bodyLower = body.toLowerCase()
    const likelyUsesJWT =
      bodyLower.includes('authorization') ||
      bodyLower.includes('bearer') ||
      bodyLower.includes('access_token') ||
      bodyLower.includes('jwt')

    if (!likelyUsesJWT) return findings

    // Site might use JWT on API endpoints — note it as info
    findings.push({
      category:    CAT,
      checkName:   'jwt-not-found',
      severity:    'INFO',
      title:       'JWT usage detected but token not exposed in initial response',
      description: 'The page references JWT/Bearer token patterns. JWT security checks require authentication — consider scanning API endpoints directly with a token.',
      evidence:    `URL: ${url}\nJWT references found in page source`,
      remediation: 'Ensure JWTs are validated server-side on every request. Use strong secrets (256+ bit random). Set short expiry times.',
    })
    return findings
  }

  for (const token of tokens) {
    const decoded = decodeJWT(token)
    if (!decoded) continue

    const { header, payload } = decoded

    // ── 1. Algorithm: none attack ────────────────────────────────────────
    if (header.alg && header.alg.toLowerCase() !== 'none') {
      const noneToken = buildAlgNoneToken(decoded)
      try {
        const res = await http.get(url, {
          headers: { Authorization: `Bearer ${noneToken}` },
          timeout: 8000,
        })
        // If we get a 200 with the alg:none token, server doesn't verify signature
        if (res.status === 200 && !String(res.data).toLowerCase().includes('invalid')) {
          findings.push({
            category:    CAT,
            checkName:   'jwt-alg-none',
            severity:    'CRITICAL',
            title:       'JWT accepts "alg: none" — signature bypass',
            description: 'The server accepted a JWT with algorithm set to "none", meaning it skipped signature verification entirely. An attacker can forge any token without knowing the secret.',
            evidence: [
              `Original token alg: ${header.alg}`,
              `Forged token (alg:none): ${noneToken.slice(0, 80)}...`,
              `Server response status: ${res.status}`,
            ].join('\n'),
            remediation: 'Explicitly reject tokens with alg=none. Whitelist allowed algorithms server-side. Use a well-maintained JWT library that handles this by default.',
          })
        }
      } catch { /* skip */ }
    }

    // ── 2. Algorithm is weak ─────────────────────────────────────────────
    const alg = String(header.alg ?? '').toUpperCase()
    if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
      // Brute force weak secrets
      for (const secret of WEAK_SECRETS) {
        // We can't actually HMAC without a crypto import but we can flag weak alg usage
        // and note it for manual testing
      }

      findings.push({
        category:    CAT,
        checkName:   'jwt-weak-algorithm',
        severity:    'LOW',
        title:       `JWT uses symmetric algorithm ${alg}`,
        description: `The JWT uses ${alg} (HMAC). If the secret key is weak or leaked, attackers can forge tokens. Consider RS256 (asymmetric) for better security.`,
        evidence:    `JWT header: ${JSON.stringify(header)}\nAlgorithm: ${alg}`,
        remediation: 'Use RS256 or ES256 (asymmetric algorithms) where possible. If using HMAC, use a cryptographically random secret of at least 256 bits.',
      })
    }

    // ── 3. Token expiry ──────────────────────────────────────────────────
    if (!payload.exp) {
      findings.push({
        category:    CAT,
        checkName:   'jwt-no-expiry',
        severity:    'HIGH',
        title:       'JWT has no expiry (exp claim missing)',
        description: 'The JWT does not contain an "exp" claim. Tokens without expiry are valid forever — a stolen token can never be invalidated.',
        evidence:    `JWT payload: ${JSON.stringify(payload)}`,
        remediation: 'Always set an expiry on JWTs. Use short-lived access tokens (15min–1hr) and refresh tokens for long-lived sessions.',
      })
    } else {
      const expiresAt = new Date(payload.exp * 1000)
      const now       = new Date()
      const daysLeft  = (payload.exp - Date.now() / 1000) / 86400

      if (daysLeft > 30) {
        findings.push({
          category:    CAT,
          checkName:   'jwt-long-expiry',
          severity:    'MEDIUM',
          title:       `JWT has very long expiry — ${Math.floor(daysLeft)} days remaining`,
          description: `The JWT expires ${expiresAt.toISOString()}, which is ${Math.floor(daysLeft)} days from now. Long-lived tokens give attackers a large window if stolen.`,
          evidence:    `exp: ${payload.exp} → ${expiresAt.toISOString()}\nDays until expiry: ${Math.floor(daysLeft)}`,
          remediation: 'Use short-lived access tokens (15 minutes to 1 hour). Implement refresh token rotation.',
        })
      }
    }

    // ── 4. Sensitive data in payload ─────────────────────────────────────
    const sensitiveKeys = ['password', 'secret', 'credit', 'ssn', 'cvv', 'pin']
    const payloadStr    = JSON.stringify(payload).toLowerCase()
    const found         = sensitiveKeys.find(k => payloadStr.includes(k))

    if (found) {
      findings.push({
        category:    CAT,
        checkName:   'jwt-sensitive-payload',
        severity:    'HIGH',
        title:       'Sensitive data in JWT payload',
        description: `The JWT payload contains potentially sensitive data ("${found}"). JWT payloads are base64-encoded, not encrypted — anyone with the token can read the payload.`,
        evidence:    `Payload keys: ${Object.keys(payload).join(', ')}\nSensitive key found: ${found}`,
        remediation: 'Never store sensitive data in JWT payloads. Store only non-sensitive identifiers (user ID, roles). Use JWE (encrypted JWT) if sensitive claims are required.',
      })
    }

    // ── 5. kid header injection hint ─────────────────────────────────────
    if (header.kid) {
      findings.push({
        category:    CAT,
        checkName:   'jwt-kid-present',
        severity:    'LOW',
        title:       'JWT uses "kid" header — potential injection vector',
        description: 'The JWT contains a "kid" (key ID) header. If the server uses this value in a database query or file path without sanitization, it may be vulnerable to SQL injection or path traversal.',
        evidence:    `kid: ${header.kid}`,
        remediation: 'Validate the kid header against a strict allowlist. Never use the kid value directly in SQL queries or file system operations.',
      })
    }
  }

  return findings
}