import 'dotenv/config'
import { Worker, Job } from 'bullmq'
import { redis }  from './redis'
import { prisma } from '../db/prisma'

const worker = new Worker(
  'scans',
  async (job: Job) => {
    const { scanId, url, checks } = job.data as { scanId: string; url: string; checks: string[] }
    console.log(`[worker] Processing scan ${scanId} for ${url}`)

    await prisma.scan.update({
      where: { id: scanId },
      data:  { status: 'RUNNING', checks: checks ?? ['all'] },
    })

    try {
      // Store the path in a typed string so TypeScript returns Promise<any>
      // instead of trying to resolve the scanner source into the api compilation.
      type RunScanFn = (url: string, checks: string[]) => Promise<{ findings: any[]; score: number }>
      const scannerPath: string = '../../../scanner/src/orchestrator'
      const { runScan } = await import(scannerPath) as { runScan: RunScanFn }
      const { findings, score } = await runScan(url, checks ?? ['all'])

      if (findings.length > 0) {
        await prisma.finding.createMany({
          data: findings.map((f: any) => ({ ...f, scanId })),
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

worker.on('failed', (job: Job | undefined, err: Error) => {
  console.error(`[worker] Job ${job?.id} failed:`, err.message)
})

console.log('[worker] Listening for scan jobs...')