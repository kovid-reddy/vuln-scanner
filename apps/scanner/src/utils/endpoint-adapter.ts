import { DiscoveredEndpoint } from './crawler'
import { http } from './http'

// Build GET test URLs by injecting payload into every param of an endpoint
export function buildGetVariantsFromEndpoint(
  endpoint: DiscoveredEndpoint,
  payload:  string,
): { testUrl: string; param: string }[] {
  const results: { testUrl: string; param: string }[] = []

  if (endpoint.params.length > 0) {
    for (const param of endpoint.params) {
      try {
        const modified = new URL(endpoint.url)
        modified.searchParams.set(param, payload)
        results.push({ testUrl: modified.toString(), param })
      } catch { /* skip malformed URLs */ }
    }
  } else {
    // No known params — try common injectable names
    for (const param of ['id', 'q', 'search', 'cat', 'page', 'user', 'item', 'query', 'name']) {
      try {
        const modified = new URL(endpoint.url)
        modified.searchParams.set(param, payload)
        results.push({ testUrl: modified.toString(), param })
      } catch { /* skip */ }
    }
  }

  return results
}

// Build POST body from endpoint params + payload
export function buildPostBodyFromEndpoint(
  endpoint: DiscoveredEndpoint,
  payload:  string,
): Record<string, string> {
  const body: Record<string, string> = {}
  for (const param of endpoint.params) {
    const lower = param.toLowerCase()
    // Don't inject into password fields — use realistic value
    body[param] = lower.includes('pass') ? 'TestPassword123!' : payload
  }
  return body
}