import * as cheerio from 'cheerio'
import { http } from './http'

export interface DiscoveredEndpoint {
  url:         string
  method:      'GET' | 'POST'
  params:      string[]
  isForm:      boolean
  formAction?: string
  depth:       number
}

function normalizeUrl(base: string, href: string): string | null {
  try {
    const resolved = new URL(href, base)
    const origin   = new URL(base).origin
    if (resolved.origin !== origin) return null
    resolved.hash = ''
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

    endpoints.push({
      url:    normalized,
      method: 'GET',
      params: extractQueryParams(normalized),
      isForm: false,
      depth,
    })

    if (depth >= maxDepth) continue

    let html = ''

    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const res = await http.get(normalized, {
          timeout: 20000,
          headers: {
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
          },
        })

        const ct = String(res.headers['content-type'] ?? '')
        if (
          ct.includes('application/json') ||
          ct.includes('image/') ||
          ct.includes('font/') ||
          ct.includes('text/css') ||
          ct.includes('application/javascript')
        ) break

        html = typeof res.data === 'string' ? res.data : JSON.stringify(res.data)
        console.log(`[crawler] Fetched ${normalized} — ${html.length} bytes`)
        break
      } catch (err: any) {
        console.log(`[crawler] Attempt ${attempt} failed for ${normalized}: ${err.message}`)
        if (attempt < 2) await new Promise(r => setTimeout(r, 2000))
      }
    }

    if (!html) continue

    const $ = cheerio.load(html)

    // ── Extract <a href> links ────────────────────────────────────────────
    $('a[href]').each((_i: number, el: any) => {
      const href     = $(el).attr('href') ?? ''
      const resolved = normalizeUrl(normalized, href)
      if (resolved && !visited.has(resolved)) {
        queue.push({ url: resolved, depth: depth + 1 })
      }
    })

    // ── Extract <form> elements ───────────────────────────────────────────
    $('form').each((_i: number, form: any) => {
      const rawAction = $(form).attr('action') || normalized
      const method    = (($(form).attr('method') || 'GET').toUpperCase()) as 'GET' | 'POST'
      const action    = normalizeUrl(normalized, rawAction) ?? normalized

      const inputs: string[] = []
      $(form).find('input[name], textarea[name], select[name]').each((_j: number, el: any) => {
        const type = ($(el).attr('type') ?? '').toLowerCase()
        const name = $(el).attr('name') ?? ''
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