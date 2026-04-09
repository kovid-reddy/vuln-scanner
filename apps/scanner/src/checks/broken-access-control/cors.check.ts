import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const EVIL_ORIGIN = 'https://evil-attacker-test.com'
const CAT = 'broken-access-control'

export async function corsCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []

  try {
    const res = await http.get(url, {
      headers: { Origin: EVIL_ORIGIN },
    })

    const acao = res.headers['access-control-allow-origin'] ?? ''
    const acac = res.headers['access-control-allow-credentials'] ?? ''

    if (acao === '*') {
      findings.push({
        category: CAT,
        checkName: 'cors-wildcard',
        severity: 'MEDIUM',
        title: 'CORS wildcard origin',
        description:
          'Server returns Access-Control-Allow-Origin: * — any website can read responses from this origin.',
        evidence: `Access-Control-Allow-Origin: ${acao}`,
        remediation:
          'Replace * with an explicit allowlist of trusted origins. Never use wildcard on authenticated endpoints.',
      })
    } else if (acao === EVIL_ORIGIN) {
      const withCreds = acac.toLowerCase() === 'true'
      findings.push({
        category: CAT,
        checkName: 'cors-origin-reflection',
        severity: withCreds ? 'CRITICAL' : 'HIGH',
        title: `CORS reflects arbitrary origin${withCreds ? ' with credentials' : ''}`,
        description: withCreds
          ? 'Server reflects the attacker Origin AND allows credentials — full authenticated cross-origin read is possible.'
          : 'Server reflects any Origin header, allowing cross-origin reads of response data.',
        evidence: `ACAO: ${acao} | ACAC: ${acac || 'not set'}`,
        remediation:
          'Validate Origin against a hardcoded allowlist. Never combine reflected origins with Access-Control-Allow-Credentials: true.',
      })
    }

    // Check preflight too
    const pre = await http.options(url, {
      headers: {
        Origin: EVIL_ORIGIN,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'authorization',
      },
    })

    const preAcao = pre.headers['access-control-allow-origin'] ?? ''
    const preAcam = pre.headers['access-control-allow-methods'] ?? ''

    if (preAcao === EVIL_ORIGIN && preAcam.includes('DELETE')) {
      findings.push({
        category: CAT,
        checkName: 'cors-preflight-dangerous-methods',
        severity: 'HIGH',
        title: 'CORS preflight allows DELETE from arbitrary origin',
        description:
          'Preflight response allows DELETE method from a reflected attacker origin.',
        evidence: `ACAO: ${preAcao} | ACAM: ${preAcam}`,
        remediation: 'Restrict allowed methods and origins in preflight responses.',
      })
    }
  } catch (err: any) {
    // Network errors are info-level — site may just be down
    findings.push({
      category: CAT,
      checkName: 'cors-check-error',
      severity: 'INFO',
      title: 'CORS check failed',
      description: `Could not reach target: ${err.message}`,
      remediation: 'Verify the URL is reachable and try again.',
    })
  }

  return findings
}
