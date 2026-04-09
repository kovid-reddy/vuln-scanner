import { FastifyInstance } from 'fastify'
import { prisma }    from '../db/prisma'
import { scanQueue } from '../queue/scan.queue'

export async function scanRoutes(app: FastifyInstance) {

  app.post<{ Body: { url: string; checks?: string[] } }>('/scan', async (req, reply) => {
  const { url, checks } = req.body ?? {}

  if (!url) return reply.status(400).send({ error: 'url is required' })
  try { new URL(url) } catch {
    return reply.status(400).send({ error: 'Invalid URL format' })
  }

  const scan = await prisma.scan.create({
    data: { url, status: 'QUEUED' },
  })

  await scanQueue.add('run-scan', {
    scanId: scan.id,
    url,
    checks: checks ?? ['all'],   // default = run everything
  }, {
    attempts: 3,
    backoff: { type: 'exponential', delay: 2000 },
  })

  return reply.status(202).send({ scanId: scan.id, status: 'QUEUED', url })
})

  app.get<{ Params: { id: string } }>('/scan/:id', async (req, reply) => {
    const scan = await prisma.scan.findUnique({
      where:   { id: req.params.id },
      include: { findings: { orderBy: { severity: 'asc' } } },
    })

  // GET /api/scans — list all scans, newest first
  // app.get('/scans', async (req, reply) => {
  //   const scans = await prisma.scan.findMany({
  //     orderBy: { startedAt: 'desc' },
  //     take: 50,
  //     include: {
  //       _count: { select: { findings: true } }
  //     }
  //   })
  //   return scans
  // })

    if (!scan) return reply.status(404).send({ error: 'Scan not found' })

    return scan
  })
}