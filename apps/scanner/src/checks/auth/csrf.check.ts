import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'
import * as cheerio from 'cheerio'

const CAT = 'auth-failures'

const CSRF_TOKEN_NAMES = [
  'csrf', 'csrf_token', '_csrf', 'csrftoken', 'csrf-token',
  'xsrf', 'xsrf_token', '_xsrf', 'xsrftoken',
  'authenticity_token', '_token', 'token',
  '__requestverificationtoken',
]

function hasCsrfToken(inputs: string[]): boolean {
  return inputs.some(name =>
    CSRF_TOKEN_NAMES.some(csrf => name.toLowerCase().includes(csrf))
  )
}

function hasOriginValidation(headers: Record<string, any>): boolean {
  // SameSite=Strict/Lax on session cookies is equivalent to CSRF protection
  const cookies = headers['set-cookie']
  if (!cookies) return false
  const lines = Array.isArray(cookies) ? cookies : [cookies]
  return lines.some(line => {
    const lower = line.toLowerCase()
    return (
      (lower.includes('samesite=strict') || lower.includes('samesite=lax')) &&
      (lower.includes('session') || lower.includes('auth') || lower.includes('token'))
    )
  })
}

export async function csrfCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []

  let html    = ''
  let headers: Record<string, any> = {}

  try {
    const res = await http.get(url, { timeout: 10000 })
    html      = String(res.data)
    headers   = res.headers as Record<string, any>
  } catch {
    return findings
  }

  const $     = cheerio.load(html)
  const forms: { action: string; method: string; inputs: string[]; hasToken: boolean }[] = []

  // Parse all forms
  $('form').each((_, form) => {
    const method  = ($(form).attr('method') ?? 'GET').toUpperCase()
    const action  = $(form).attr('action') ?? url
    const inputs: string[] = []

    $(form).find('input[name], textarea[name], select[name]').each((_, el) => {
      const name = $(el).attr('name') ?? ''
      if (name) inputs.push(name)
    })

    if (method === 'POST' && inputs.length > 0) {
      forms.push({
        action,
        method,
        inputs,
        hasToken: hasCsrfToken(inputs),
      })
    }
  })

  const hasSessionCookieSameSite = hasOriginValidation(headers)

  // Check each POST form for CSRF token
  for (const form of forms) {
    if (!form.hasToken && !hasSessionCookieSameSite) {
      findings.push({
        category:    CAT,
        checkName:   'csrf-missing-token',
        severity:    'HIGH',
        title:       `CSRF token missing on POST form — "${new URL(form.action, url).pathname}"`,
        description: `A state-changing POST form has no CSRF token and the session cookie lacks SameSite protection. An attacker can trick authenticated users into submitting this form from a malicious site.`,
        evidence: [
          `Form action: ${form.action}`,
          `Method: ${form.method}`,
          `Fields: ${form.inputs.join(', ')}`,
          `CSRF token found: false`,
          `Session cookie SameSite: ${hasSessionCookieSameSite ? 'yes' : 'no'}`,
        ].join('\n'),
        remediation: 'Add a CSRF token to every state-changing form. Use the Synchronizer Token Pattern or Double Submit Cookie. Alternatively set SameSite=Strict on session cookies.',
      })
    }
  }

  // Check CORS headers for CSRF amplification
  const acao = String(headers['access-control-allow-origin'] ?? '')
  const acac = String(headers['access-control-allow-credentials'] ?? '')

  if (acao === '*' && acac.toLowerCase() === 'true') {
    findings.push({
      category:    CAT,
      checkName:   'csrf-cors-amplification',
      severity:    'CRITICAL',
      title:       'CORS wildcard + credentials enables cross-origin CSRF',
      description: 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true allows any website to make authenticated cross-origin requests — amplifying CSRF to full credential theft.',
      evidence:    `ACAO: ${acao}\nACAC: ${acac}`,
      remediation: 'Never combine wildcard CORS with Allow-Credentials. Use an explicit origin allowlist.',
    })
  }

  // No POST forms found — still check for missing CSRF headers on API
  if (forms.length === 0) {
    const csrfHeader = String(headers['x-csrf-token'] ?? headers['x-xsrf-token'] ?? '')
    if (!csrfHeader && !hasSessionCookieSameSite) {
      findings.push({
        category:    CAT,
        checkName:   'csrf-no-protection-detected',
        severity:    'MEDIUM',
        title:       'No CSRF protection mechanism detected',
        description: 'No CSRF tokens in forms, no SameSite cookie attributes, and no CSRF headers were detected. If this endpoint processes state-changing requests, it may be vulnerable.',
        evidence:    `URL: ${url}\nX-CSRF-Token: absent\nX-XSRF-Token: absent\nSameSite cookies: none`,
        remediation: 'Implement CSRF tokens for all state-changing operations. Use SameSite=Lax or Strict on session cookies as a minimum defence.',
      })
    }
  }

  return findings
}