import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'injection'
const DEBUG = false

function log(...args: any[]) { if (DEBUG) console.log('[cmdi]', ...args) }

// Each payload has markers we look for in the response
const PAYLOADS = [
  // Unix — id command output
  { payload: '; id',                    markers: ['uid=', 'gid='],        os: 'Unix'    },
  { payload: '| id',                    markers: ['uid=', 'gid='],        os: 'Unix'    },
  { payload: '`id`',                    markers: ['uid=', 'gid='],        os: 'Unix'    },
  { payload: '$(id)',                   markers: ['uid=', 'gid='],        os: 'Unix'    },
  { payload: '; whoami',                markers: ['root', 'www-data', 'apache', 'nginx'], os: 'Unix' },
  { payload: '| whoami',                markers: ['root', 'www-data', 'apache', 'nginx'], os: 'Unix' },
  { payload: '; cat /etc/passwd',       markers: ['root:x:', 'daemon:'],  os: 'Unix'    },
  { payload: '| cat /etc/passwd',       markers: ['root:x:', 'daemon:'],  os: 'Unix'    },
  { payload: '; ls',                    markers: ['index', 'config', 'var', 'usr'], os: 'Unix' },
  // Windows
  { payload: '& whoami',               markers: ['nt authority', 'system', 'administrator'], os: 'Windows' },
  { payload: '| whoami',               markers: ['nt authority', 'system', 'administrator'], os: 'Windows' },
  { payload: '& dir',                  markers: ['volume', 'directory of', 'bytes free'],    os: 'Windows' },
  { payload: '; dir',                  markers: ['volume', 'directory of', 'bytes free'],    os: 'Windows' },
  // Time-based (blind) — if execution delayed, command ran
  { payload: '; sleep 5',              markers: [],  os: 'Unix (time-based)',    sleepMs: 5000 },
  { payload: '| sleep 5',              markers: [],  os: 'Unix (time-based)',    sleepMs: 5000 },
  { payload: '& timeout /t 5',         markers: [],  os: 'Windows (time-based)', sleepMs: 5000 },
  { payload: '$(sleep 5)',             markers: [],  os: 'Unix (time-based)',    sleepMs: 5000 },
]

// Common params that get passed to shell commands
const SHELL_PARAMS = [
  'host', 'ip', 'cmd', 'exec', 'command', 'ping',
  'query', 'search', 'file', 'path', 'dir',
  'url', 'domain', 'target', 'address',
]

function buildGetVariants(url: string, payload: string): { testUrl: string; param: string }[] {
  const parsed  = new URL(url)
  const results: { testUrl: string; param: string }[] = []

  for (const key of parsed.searchParams.keys()) {
    const modified = new URL(url)
    modified.searchParams.set(key, `127.0.0.1${payload}`)  // prefix with valid value
    results.push({ testUrl: modified.toString(), param: key })
  }

  // Also try shell-adjacent param names even if not in URL
  for (const param of SHELL_PARAMS) {
    if (!parsed.searchParams.has(param)) {
      const modified = new URL(url)
      modified.searchParams.set(param, `127.0.0.1${payload}`)
      results.push({ testUrl: modified.toString(), param })
    }
  }

  return results
}

function containsCommandOutput(body: string, markers: string[]): string | null {
  const lower = body.toLowerCase()
  return markers.find(m => lower.includes(m.toLowerCase())) ?? null
}

export async function osCommandCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  // ── 1. Output-based detection ─────────────────────────────────────────────
  for (const { payload, markers, os } of PAYLOADS.filter(p => p.markers.length > 0)) {
    const variants = buildGetVariants(url, payload)

    for (const { testUrl, param } of variants) {
      const key = `cmdi-${param}`
      if (reported.has(key)) continue

      try {
        const res  = await http.get(testUrl, { timeout: 10000 })
        const body = String(res.data)
        const hit  = containsCommandOutput(body, markers)

        log(`param="${param}" os=${os} hit=${hit}`)

        if (hit) {
          reported.add(key)
          findings.push({
            category:    CAT,
            checkName:   'os-command-injection',
            severity:    'CRITICAL',
            title:       `OS command injection (${os}) — param "${param}"`,
            description: `The server executed an injected OS command. Command output was found in the HTTP response, confirming remote code execution via parameter "${param}".`,
            evidence: [
              `URL: ${testUrl}`,
              `Payload: 127.0.0.1${payload}`,
              `OS: ${os}`,
              `Command output marker found: "${hit}"`,
              `Response snippet: ${body.slice(0, 300)}`,
            ].join('\n'),
            remediation: 'Never pass user input to shell execution functions (exec, system, popen, etc.). Use language-native libraries instead of shelling out. If shell is required, use strict allowlists and never interpolate user data.',
          })
          break
        }
      } catch (err: any) {
        log(`Request failed: ${err.message}`)
      }
    }

    if (findings.length > 0) break
  }

  // ── 2. Time-based blind detection ────────────────────────────────────────
  if (findings.length === 0) {
    for (const { payload, os, sleepMs } of PAYLOADS.filter(p => p.sleepMs)) {
      const variants = buildGetVariants(url, payload)

      for (const { testUrl, param } of variants.slice(0, 3)) {  // limit time-based probes
        const key = `cmdi-time-${param}`
        if (reported.has(key)) continue

        try {
          const start   = Date.now()
          await http.get(testUrl, { timeout: 12000 })
          const elapsed = Date.now() - start

          log(`Time-based: param="${param}" elapsed=${elapsed}ms threshold=${sleepMs! * 0.8}ms`)

          if (elapsed >= sleepMs! * 0.8) {
            reported.add(key)
            findings.push({
              category:    CAT,
              checkName:   'os-command-injection-blind',
              severity:    'CRITICAL',
              title:       `OS command injection — blind time-based (${os}) — param "${param}"`,
              description: `A sleep/delay command payload caused the server to respond ${(elapsed / 1000).toFixed(1)}s later than normal, indicating the OS command was executed.`,
              evidence: [
                `URL: ${testUrl}`,
                `Payload: 127.0.0.1${payload}`,
                `OS: ${os}`,
                `Response time: ${elapsed}ms (expected delay: ${sleepMs}ms)`,
              ].join('\n'),
              remediation: 'Never pass user input to shell functions. This is blind RCE — the attacker cannot see output but can exfiltrate data via DNS or HTTP callbacks.',
            })
            break
          }
        } catch (err: any) {
          log(`Time-based request failed: ${err.message}`)
        }
      }

      if (findings.length > 0) break
    }
  }

  // ── 3. POST body check ────────────────────────────────────────────────────
  if (findings.length === 0) {
    for (const { payload, markers, os } of PAYLOADS.filter(p => p.markers.length > 0).slice(0, 6)) {
      const body: Record<string, string> = {}
      for (const param of ['host', 'ip', 'cmd', 'command', 'ping', 'target']) {
        body[param] = `127.0.0.1${payload}`
      }

      try {
        const res  = await http.post(url, body, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000,
        })
        const text = String(res.data)
        const hit  = containsCommandOutput(text, markers)

        if (hit) {
          findings.push({
            category:    CAT,
            checkName:   'os-command-injection-post',
            severity:    'CRITICAL',
            title:       `OS command injection (${os}) — POST body`,
            description: 'A POST body field was passed to an OS command. Command output appeared in the response, confirming RCE.',
            evidence:    `URL: ${url}\nPayload: 127.0.0.1${payload}\nMarker found: "${hit}"\nSnippet: ${text.slice(0, 300)}`,
            remediation: 'Never pass POST body fields to shell execution functions. Validate and sanitize all inputs.',
          })
          break
        }
      } catch { /* skip */ }
    }
  }

  return findings
}