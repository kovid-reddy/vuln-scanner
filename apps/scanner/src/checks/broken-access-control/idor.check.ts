import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'broken-access-control'

// Extract all numeric-looking param values from a URL
function extractNumericParams(url: string): { key: string; value: number }[] {
  const parsed = new URL(url)
  const results: { key: string; value: number }[] = []

  for (const [key, val] of parsed.searchParams.entries()) {
    const num = parseInt(val, 10)
    if (!isNaN(num) && num > 0 && String(num) === val) {
      results.push({ key, value: num })
    }
  }

  // Also check path segments: /users/123, /posts/456
  const pathNums = parsed.pathname.match(/\/(\d+)/g)
  if (pathNums) {
    pathNums.forEach((segment, i) => {
      const num = parseInt(segment.replace('/', ''), 10)
      results.push({ key: `__path_segment_${i}`, value: num })
    })
  }

  return results
}

function buildVariantUrl(original: string, key: string, newValue: number): string {
  const parsed = new URL(original)

  if (key.startsWith('__path_segment_')) {
    // Replace numeric segment in path
    parsed.pathname = parsed.pathname.replace(/\/\d+/, `/${newValue}`)
  } else {
    parsed.searchParams.set(key, String(newValue))
  }

  return parsed.toString()
}

export async function idorCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const params = extractNumericParams(url)

  if (params.length === 0) return findings  // no numeric IDs to probe

  // Get the baseline response for the original URL
  let baselineStatus: number
  let baselineLength: number
  try {
    const baseline = await http.get(url)
    baselineStatus = baseline.status
    baselineLength = String(baseline.data).length
  } catch {
    return findings   // can't reach target at all
  }

  // Only probe if baseline returned a real resource
  if (![200, 201].includes(baselineStatus)) return findings

  for (const { key, value } of params) {
    // Probe IDs: value-2, value-1, value+1, value+2
    const probeOffsets = [-2, -1, 1, 2]
    const probeValues  = probeOffsets
      .map(o => value + o)
      .filter(v => v > 0)     // skip non-positive IDs

    for (const probe of probeValues) {
      const probeUrl = buildVariantUrl(url, key, probe)

      try {
        const res = await http.get(probeUrl)

        if (
          res.status === 200 &&
          Math.abs(String(res.data).length - baselineLength) < baselineLength * 0.5
        ) {
          // Other IDs return similar-sized 200 responses — likely IDOR
          findings.push({
            category:    CAT,
            checkName:   'idor',
            severity:    'HIGH',
            title:       `Possible IDOR on parameter "${key}"`,
            description: `Changing ${key}=${value} to ${key}=${probe} returned HTTP 200 with a similar response body. This suggests object-level access control may not be enforced.`,
            evidence:    `Original: ${url} → ${baselineStatus}\nProbe:    ${probeUrl} → ${res.status} (${String(res.data).length} bytes)`,
            remediation:
              'Enforce object-level authorization on every resource endpoint. Validate that the authenticated user owns or has permission to access the requested resource ID.',
          })
          break   // one finding per param is enough
        }
      } catch {
        // probe failed — skip
      }
    }
  }

  return findings
}