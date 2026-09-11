import * as cheerio from 'cheerio'
import { http } from './http'

// ── Response size limit ───────────────────────────────────────────────────────
// Reject any HTTP response body larger than this before it fully loads.
// Axios v1 enforces maxContentLength per-chunk during streaming — the connection
// is aborted before the full body reaches memory, preventing OOM on large pages.
// Override via environment variable: CRAWLER_MAX_RESPONSE_BYTES=5242880 (5 MB)
const MAX_RESPONSE_BYTES = Number(process.env.CRAWLER_MAX_RESPONSE_BYTES) || 2 * 1024 * 1024 // 2 MB default

// URL path extensions that are never useful to crawl.
// We skip these before making any HTTP request.
const BINARY_EXTENSIONS = new Set([
  '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp', '.tiff',
  '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.mov', '.avi',
  '.woff', '.woff2', '.ttf', '.eot',
  '.exe', '.dmg', '.pkg', '.deb', '.rpm',
  '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx',
])

export interface DiscoveredEndpoint {
  url:         string
  method:      'GET' | 'POST'
  params:      string[]
  isForm:      boolean
  formAction?: string
  depth:       number
}

// ── URL helpers ───────────────────────────────────────────────────────────────

function isBinaryExtension(url: string): boolean {
  try {
    const pathname = new URL(url).pathname.toLowerCase()
    const dot = pathname.lastIndexOf('.')
    if (dot === -1) return false
    return BINARY_EXTENSIONS.has(pathname.slice(dot))
  } catch {
    return false
  }
}

/**
 * Normalise a discovered href relative to the current page.
 * Returns null if the resolved URL:
 *  - belongs to a different origin (domain), OR
 *  - falls outside the start URL's base path.
 *
 * The basePath restriction prevents the crawler from wandering across an
 * entire shared-domain host (e.g. GitHub Pages, Netlify) when the target
 * is hosted at a subpath such as /www-project-juice-shop/.
 */
function normalizeUrl(base: string, href: string, basePath: string): string | null {
  try {
    const resolved = new URL(href, base)
    const origin   = new URL(base).origin

    // Must stay on the same origin
    if (resolved.origin !== origin) return null

    // Must stay within the target's base path.
    // basePath='/' means the target is at the domain root → no restriction.
    // basePath='/www-project-juice-shop' means only follow URLs under that prefix.
    if (basePath !== '/') {
      const p = resolved.pathname
      if (p !== basePath && !p.startsWith(basePath + '/')) return null
    }

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

// ── Main crawl function ───────────────────────────────────────────────────────

export async function crawl(
  startUrl: string,
  maxPages: number = 40,
  maxDepth: number = 3,
): Promise<DiscoveredEndpoint[]> {
  const visited   = new Set<string>()
  const queue:    { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }]
  const endpoints: DiscoveredEndpoint[] = []

  // Derive the base path from the start URL.
  // For 'https://example.com/'                  → basePath = '/'
  // For 'https://owasp.github.io/juice-shop/'   → basePath = '/juice-shop'
  // This prevents the crawler from following links to sibling paths on shared hosts.
  const startPathname = new URL(startUrl).pathname.replace(/\/$/, '') || '/'
  const basePath      = startPathname

  console.log(`[crawler] Starting from ${startUrl} (max ${maxPages} pages, depth ${maxDepth}, basePath "${basePath}", maxResponseBytes ${MAX_RESPONSE_BYTES})`)

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift()
    if (!item) break

    const { url, depth } = item
    const normalized = url.split('#')[0]
    if (visited.has(normalized)) continue
    visited.add(normalized)

    // Skip binary/non-HTML URLs immediately — no HTTP request needed
    if (isBinaryExtension(normalized)) {
      console.log(`[crawler] Skipping binary URL: ${normalized}`)
      continue
    }

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
          // Abort the response stream once accumulated bytes exceed the limit.
          // Axios v1 checks this per-chunk, so the full body never loads into memory.
          maxContentLength: MAX_RESPONSE_BYTES,
          headers: {
            'Accept':          'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
          },
        })

        // Only process HTML pages — skip PDFs, JSON, CSS, JS, images, etc.
        // This is a whitelist check: if the server didn't say it's HTML, skip it.
        const ct = String(res.headers['content-type'] ?? '')
        if (!ct.includes('text/html') && !ct.includes('application/xhtml')) {
          console.log(`[crawler] Skipping non-HTML response: ${normalized} (${ct})`)
          break
        }

        html = typeof res.data === 'string' ? res.data : JSON.stringify(res.data)
        console.log(`[crawler] Fetched ${normalized} — ${html.length} bytes`)
        break
      } catch (err: any) {
        // Includes axios maxContentLength errors — page is skipped gracefully
        console.log(`[crawler] Attempt ${attempt} failed for ${normalized}: ${err.message}`)
        if (attempt < 2) await new Promise(r => setTimeout(r, 2000))
      }
    }

    if (!html) continue

    const $ = cheerio.load(html)

    // ── Extract <a href> links ────────────────────────────────────────────
    $('a[href]').each((_i: number, el: any) => {
      const href     = $(el).attr('href') ?? ''
      const resolved = normalizeUrl(normalized, href, basePath)
      if (resolved && !visited.has(resolved)) {
        queue.push({ url: resolved, depth: depth + 1 })
      }
    })

    // ── Extract <form> elements ───────────────────────────────────────────
    $('form').each((_i: number, form: any) => {
      const rawAction = $(form).attr('action') || normalized
      const method    = (($(form).attr('method') || 'GET').toUpperCase()) as 'GET' | 'POST'
      const action    = normalizeUrl(normalized, rawAction, basePath) ?? normalized

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
      ...scriptText.matchAll(/['\"`](\/api\/[^'\"`\s?#]{2,60})['\"`]/g),
      ...scriptText.matchAll(/fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]/g),
      ...scriptText.matchAll(/axios\.[a-z]+\s*\(\s*['\"`]([^'\"`]+)['\"`]/g),
    ]

    for (const match of apiMatches) {
      const resolved = normalizeUrl(normalized, match[1], basePath)
      if (resolved && !visited.has(resolved)) {
        queue.push({ url: resolved, depth: depth + 1 })
      }
    }
  }

  const deduped = deduplicateEndpoints(endpoints)
  console.log(`[crawler] Found ${deduped.length} unique endpoints across ${visited.size} pages`)
  return deduped
}