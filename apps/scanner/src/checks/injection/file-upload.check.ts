import { http } from '../../utils/http'
import { Finding } from '@vuln-scanner/shared-types'
import * as cheerio from 'cheerio'

const CAT = 'injection'

// Malicious file types disguised as images
const UPLOAD_PAYLOADS = [
  {
    filename:    'test.php',
    content:     '<?php echo "VULN_CONFIRMED_" . phpversion(); ?>',
    contentType: 'image/jpeg',
    marker:      'VULN_CONFIRMED_',
    label:       'PHP webshell as JPEG',
  },
  {
    filename:    'test.php5',
    content:     '<?php echo "VULN_CONFIRMED_PHP5"; ?>',
    contentType: 'image/png',
    marker:      'VULN_CONFIRMED_PHP5',
    label:       'PHP5 webshell as PNG',
  },
  {
    filename:    'test.phtml',
    content:     '<?php echo "VULN_CONFIRMED_PHTML"; ?>',
    contentType: 'image/gif',
    marker:      'VULN_CONFIRMED_PHTML',
    label:       'PHTML webshell as GIF',
  },
  {
    filename:    'test.jsp',
    content:     '<% out.println("VULN_CONFIRMED_JSP"); %>',
    contentType: 'image/jpeg',
    marker:      'VULN_CONFIRMED_JSP',
    label:       'JSP webshell as JPEG',
  },
  {
    filename:    'test.html',
    content:     '<script>document.write("VULN_CONFIRMED_HTML")</script>',
    contentType: 'image/jpeg',
    marker:      'VULN_CONFIRMED_HTML',
    label:       'HTML/XSS file as JPEG',
  },
  {
    filename:    'test.svg',
    content:     '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("VULN_CONFIRMED_SVG")</script></svg>',
    contentType: 'image/svg+xml',
    marker:      'VULN_CONFIRMED_SVG',
    label:       'SVG with embedded XSS',
  },
]

// Double extension bypass attempts
const DOUBLE_EXT_PAYLOADS = [
  { filename: 'test.php.jpg',  contentType: 'image/jpeg', label: 'Double extension .php.jpg' },
  { filename: 'test.php%00.jpg', contentType: 'image/jpeg', label: 'Null byte bypass .php%00.jpg' },
  { filename: 'test.PhP',      contentType: 'image/jpeg', label: 'Case variation .PhP'         },
  { filename: 'test.php.',     contentType: 'image/jpeg', label: 'Trailing dot bypass .php.'   },
]

function buildMultipartBody(
  filename:    string,
  content:     string,
  contentType: string,
  fieldName:   string = 'file',
): { body: Buffer; boundary: string } {
  const boundary = `----FormBoundary${Math.random().toString(36).slice(2)}`
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\n`),
    Buffer.from(`Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n`),
    Buffer.from(`Content-Type: ${contentType}\r\n\r\n`),
    Buffer.from(content),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ])
  return { body, boundary }
}

async function findUploadEndpoints(url: string): Promise<{ action: string; fieldName: string }[]> {
  const endpoints: { action: string; fieldName: string }[] = []

  try {
    const res  = await http.get(url, { timeout: 10000 })
    const html = String(res.data)
    const $ = cheerio.load(html)

    $('form').each((_: any, form: any) => {
      const enctype = $(form).attr('enctype') ?? ''
      const action  = $(form).attr('action') ?? url
      const method  = ($(form).attr('method') ?? 'GET').toUpperCase()

      // Only check forms with multipart encoding or file inputs
      const hasFileInput = $(form).find('input[type="file"]').length > 0
      const isMultipart  = enctype.includes('multipart')

      if ((hasFileInput || isMultipart) && method === 'POST') {
        const fileInput = $(form).find('input[type="file"]').first()
        const fieldName = fileInput.attr('name') ?? 'file'
        const resolvedAction = new URL(action, url).toString()
        endpoints.push({ action: resolvedAction, fieldName })
      }
    })
  } catch { /* skip */ }

  // Also try common upload paths even if not found in forms
  const commonPaths = [
    '/upload', '/uploads', '/upload.php', '/file-upload',
    '/api/upload', '/api/files', '/admin/upload',
    '/profile/avatar', '/profile/photo', '/user/avatar',
  ]

  const base = new URL(url).origin
  for (const path of commonPaths) {
    endpoints.push({ action: `${base}${path}`, fieldName: 'file' })
  }

  return endpoints
}

export async function fileUploadCheck(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const reported = new Set<string>()

  const uploadEndpoints = await findUploadEndpoints(url)

  for (const { action, fieldName } of uploadEndpoints) {
    if (reported.has(action)) continue

    // ── Test 1: Can we upload a file at all? ────────────────────────────
    let uploadWorks = false
    let uploadedPath = ''

    for (const payload of UPLOAD_PAYLOADS) {
      try {
        const { body, boundary } = buildMultipartBody(
          payload.filename,
          payload.content,
          payload.contentType,
          fieldName,
        )

        const res = await http.post(action, body, {
          headers: {
            'Content-Type': `multipart/form-data; boundary=${boundary.slice(2)}`,
          },
          timeout: 10000,
        })

        const resText = String(res.data)

        // Check if upload was accepted
        if (res.status === 200 || res.status === 201) {
          uploadWorks = true

          // Try to find where the file was uploaded
          const pathMatch = resText.match(/(?:href|src|url|path|file)["']?\s*[:=]\s*["']?([^"'\s<>]+\.(php|jsp|html|svg|phtml|php5))/i)
          if (pathMatch) uploadedPath = pathMatch[1]

          // ── Test 2: Is the uploaded file executable? ──────────────────
          if (uploadedPath) {
            const fileUrl = new URL(uploadedPath, url).toString()
            try {
              const execRes = await http.get(fileUrl, { timeout: 8000 })
              const execBody = String(execRes.data)

              if (execBody.includes(payload.marker)) {
                reported.add(action)
                findings.push({
                  category:    CAT,
                  checkName:   'file-upload-rce',
                  severity:    'CRITICAL',
                  title:       `File upload RCE — ${payload.label}`,
                  description: `A malicious file (${payload.filename}) was uploaded and executed server-side. The server processed the file as code rather than storing it safely, enabling Remote Code Execution.`,
                  evidence: [
                    `Upload endpoint: ${action}`,
                    `Uploaded file: ${payload.filename}`,
                    `Content-Type sent: ${payload.contentType}`,
                    `Executed at: ${fileUrl}`,
                    `Execution marker found: "${payload.marker}"`,
                  ].join('\n'),
                  remediation: 'Validate file extensions against a strict allowlist. Store uploads outside the web root. Rename uploaded files to random names. Never serve user-uploaded files with execute permissions.',
                })
                break
              }
            } catch { /* file not accessible — still flag the upload */ }
          }

          // Even if we can't confirm execution, flag that dangerous files are accepted
          if (!reported.has(action)) {
            reported.add(action)
            findings.push({
              category:    CAT,
              checkName:   'file-upload-dangerous-type',
              severity:    'HIGH',
              title:       `Upload accepts dangerous file type — ${payload.filename}`,
              description: `The upload endpoint accepted a ${payload.filename} file disguised as an image. Even if not immediately executable, this file could be served to users or executed if server configuration changes.`,
              evidence: [
                `Upload endpoint: ${action}`,
                `File accepted: ${payload.filename}`,
                `Content-Type sent: ${payload.contentType}`,
                `Server response: ${res.status}`,
                uploadedPath ? `Uploaded to: ${uploadedPath}` : 'Upload path not disclosed',
              ].join('\n'),
              remediation: 'Validate file type by reading magic bytes, not just the extension or Content-Type header. Use an allowlist of safe types (jpg, png, gif, pdf). Rename files on upload.',
            })
          }
          break
        }
      } catch { /* skip failed uploads */ }
    }

    // ── Test 3: Double extension + bypass attempts ─────────────────────
    if (uploadWorks && !reported.has(`bypass-${action}`)) {
      for (const bypass of DOUBLE_EXT_PAYLOADS) {
        try {
          const { body, boundary } = buildMultipartBody(
            bypass.filename,
            '<?php echo "bypass"; ?>',
            bypass.contentType,
            fieldName,
          )

          const res = await http.post(action, body, {
            headers: {
              'Content-Type': `multipart/form-data; boundary=${boundary.slice(2)}`,
            },
            timeout: 8000,
          })

          if (res.status === 200 || res.status === 201) {
            reported.add(`bypass-${action}`)
            findings.push({
              category:    CAT,
              checkName:   'file-upload-bypass',
              severity:    'HIGH',
              title:       `Upload filter bypass — ${bypass.label}`,
              description: `The upload filter was bypassed using "${bypass.filename}". Attackers can use extension tricks to upload executable files even when basic filtering is in place.`,
              evidence: [
                `Upload endpoint: ${action}`,
                `Bypass filename: ${bypass.filename}`,
                `Server accepted: ${res.status}`,
              ].join('\n'),
              remediation: 'Use a strict allowlist of permitted extensions. Normalize filenames before checking. Check file magic bytes. Never rely solely on extension or Content-Type filtering.',
            })
            break
          }
        } catch { /* skip */ }
      }
    }
  }

  return findings
}
