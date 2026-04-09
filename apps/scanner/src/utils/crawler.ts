import * as cheerio from 'cheerio'
import { http } from './http'

export interface DiscoveredEndpoint {
  url:         string
  method:      'GET' | 'POST'
  params:      string[]       // query param names (GET) or input field names (POST)
  isForm:      boolean
  formAction?: string
  depth:       number
}

function normalizeUrl(base: string, href: string): string | null {
  try {
    const resolved = new URL(href, base)
    const origin   = new URL(base).origin
    // Only follow same-origin links
    if (resolved.origin !== origin) return null
    // Drop fragments
    resolved.hash = ''
    // Drop trailing slash variations
    return resolved.toString()
  } catch {
    return null
  }
}

function extractQueryParams(url: string): string[] {
  try {
    return [...new URL(url).searchParams.keys()]
  } catch {
    return []
  }
}

function deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const seen = new Set<string>()
  return endpoints.filter(e => {
    // Dedupe by method + path (ignore param values — same path with diff values = same endpoint)
    const parsed = new URL(e.url)
    const key    = `${e.method}:${parsed.origin}${parsed.pathname}:${e.params.sort().join(',')}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export async function crawl(
  startUrl: string,
  maxPages: number = 40,
  maxDepth: number = 3,
): Promise<DiscoveredEndpoint[]> {
  const origin    = new URL(startUrl).origin
  const visited   = new Set<string>()
  const queue:    { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }]
  const endpoints: DiscoveredEndpoint[] = []

  console.log(`[crawler] Starting from ${startUrl} (max ${maxPages} pages, depth ${maxDepth})`)

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift()
    if (!item) break

    const { url, depth } = item
    const normalized = url.split('#')[0]
    if (visited.has(normalized)) continue
    visited.add(normalized)

    // Always add this URL as a GET endpoint
    endpoints.push({
      url:    normalized,
      method: 'GET',
      params: extractQueryParams(normalized),
      isForm: false,
      depth,
    })

    // Don't fetch if at max depth
    if (depth >= maxDepth) continue

    // let html = ''
    // try {
    //   const res = await http.get(normalized, { timeout: 8000 })

    //   // Skip non-HTML responses
    //   const ct = String(res.headers['content-type'] ?? '')
    //   if (
    //     ct.includes('application/json') ||
    //     ct.includes('image/') ||
    //     ct.includes('font/') ||
    //     ct.includes('text/css') ||
    //     ct.includes('application/javascript')
    //   ) continue

    //   html = typeof res.data === 'string'
    //     ? res.data
    //     : JSON.stringify(res.data)
    // } catch {
    //   continue  // unreachable page — skip silently
    // }

    let html = ''
    let fetchSuccess = false

    // Retry once on timeout
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const res = await http.get(normalized, {
          timeout: 20000,
          headers: {
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
          }
        })

        const ct = String(res.headers['content-type'] ?? '')
        if (
          ct.includes('application/json') ||
          ct.includes('image/') ||
          ct.includes('font/') ||
          ct.includes('text/css') ||
          ct.includes('application/javascript')
        ) { fetchSuccess = true; break }

        html = typeof res.data === 'string' ? res.data : JSON.stringify(res.data)
        console.log(`[crawler] Fetched ${normalized} — ${html.length} bytes, links found: ${(html.match(/<a\s/gi) ?? []).length}`)
        fetchSuccess = true
        break
      } catch (err: any) {
        console.log(`[crawler] Attempt ${attempt} failed for ${normalized}: ${err.message}`)
        if (attempt === 2) continue
        await new Promise(r => setTimeout(r, 2000))  // wait 2s before retry
      }
    }

    if (!html) continue

    const $ = cheerio.load(html)

    // ── Extract <a href> links ────────────────────────────────────────────
    $('a[href]').each((_, el) => {
      const href     = $(el).attr('href') ?? ''
      const resolved = normalizeUrl(normalized, href)
      if (resolved && !visited.has(resolved)) {
        queue.push({ url: resolved, depth: depth + 1 })
      }
    })

    // ── Extract <form> elements ───────────────────────────────────────────
    $('form').each((_, form) => {
      const rawAction = $(form).attr('action') || normalized
      const method    = (($(form).attr('method') || 'GET').toUpperCase()) as 'GET' | 'POST'
      const action    = normalizeUrl(normalized, rawAction) ?? normalized

      const inputs: string[] = []
      $(form).find('input[name], textarea[name], select[name]').each((_, el) => {
        const type = ($(el).attr('type') ?? '').toLowerCase()
        const name = $(el).attr('name') ?? ''
        // Skip submit/button/image but keep hidden fields (they can be injectable)
        if (name && !['submit', 'button', 'image'].includes(type)) {
          inputs.push(name)
        }
      })

      if (inputs.length > 0) {
        endpoints.push({
          url:        action,
          method,
          params:     inputs,
          isForm:     true,
          formAction: action,
          depth,
        })

        // If form action is a new URL, add it to crawl queue too
        if (!visited.has(action)) {
          queue.push({ url: action, depth: depth + 1 })
        }
      }
    })

    // ── Sniff JS for API endpoint hints ──────────────────────────────────
    const scriptText = $('script:not([src])').text()
    const apiMatches = [
      ...scriptText.matchAll(/['"`](\/api\/[^'"`\s?#]{2,60})['"`]/g),
      ...scriptText.matchAll(/fetch\s*\(\s*['"`]([^'"`]+)['"`]/g),
      ...scriptText.matchAll(/axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g),
    ]

    for (const match of apiMatches) {
      const resolved = normalizeUrl(normalized, match[1])
      if (resolved && !visited.has(resolved)) {
        queue.push({ url: resolved, depth: depth + 1 })
      }
    }
  }

  const deduped = deduplicateEndpoints(endpoints)
  console.log(`[crawler] Found ${deduped.length} unique endpoints across ${visited.size} pages`)
  return deduped
}