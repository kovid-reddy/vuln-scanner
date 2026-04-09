import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { prisma }    from '../db/prisma'
import { scanQueue } from '../queue/scan.queue'

export async function scanRoutes(app: FastifyInstance) {

  app.post('/scan', async (
    req: FastifyRequest<{ Body: { url: string; checks?: string[] } }>,
    reply: FastifyReply,
  ) => {
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
      checks: checks ?? ['all'],
    }, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    })

    return reply.status(202).send({ scanId: scan.id, status: 'QUEUED', url })
  })

  app.get('/scan/:id', async (
    req: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) => {
    const scan = await prisma.scan.findUnique({
      where:   { id: req.params.id },
      include: { findings: { orderBy: { severity: 'asc' } } },
    })

    if (!scan) return reply.status(404).send({ error: 'Scan not found' })

    return scan
  })
}