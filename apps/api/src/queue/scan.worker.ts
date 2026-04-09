import 'dotenv/config'
import { Worker } from 'bullmq'
import { redis }  from './redis'
import { prisma } from '../db/prisma'

const worker = new Worker(
  'scans',
  async (job) => {
    const { scanId, url, checks } = job.data
    console.log(`[worker] Processing scan ${scanId} for ${url}`)

    await prisma.scan.update({
      where: { id: scanId },
      data:  { status: 'RUNNING', checks: checks ?? ['all'] },
    })

    try {
      // Dynamic import so the worker can resolve the scanner package
      const { runScan } = await import('../../../scanner/src/orchestrator')
      const { findings, score } = await runScan(url, checks ?? ['all'])

      if (findings.length > 0) {
        await prisma.finding.createMany({
          data: findings.map(f => ({ ...f, scanId })),
        })
      }

      await prisma.scan.update({
        where: { id: scanId },
        data:  { status: 'DONE', score, finishedAt: new Date() },
      })

      console.log(`[worker] Scan ${scanId} complete — score: ${score}`)
    } catch (err) {
      console.error(`[worker] Scan ${scanId} failed:`, err)
      await prisma.scan.update({
        where: { id: scanId },
        data:  { status: 'FAILED' },
      })
      throw err
    }
  },
  { connection: redis, 
    concurrency: 2, 
    lockDuration: 300000 /* 5 minutes */ },
)

worker.on('failed', (job, err) => {
  console.error(`[worker] Job ${job?.id} failed:`, err.message)
})

console.log('[worker] Listening for scan jobs...')