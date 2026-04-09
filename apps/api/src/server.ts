import 'dotenv/config'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import { scanRoutes } from './routes/scan.routes'
import './queue/scan.worker'   // start BullMQ worker in the same process

const app = Fastify({ logger: { level: 'info' } })

app.register(cors, {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true)
    // Allow any localhost port (development)
    if (origin.includes('localhost')) return callback(null, true)
    // Allow all Vercel deployments (preview + production)
    if (origin.includes('vercel.app')) return callback(null, true)
    return callback(new Error('Not allowed by CORS'), false)
  },
  credentials: true,
})

app.register(scanRoutes, { prefix: '/api' })

app.get('/health', async () => ({
  status: 'ok',
  timestamp: new Date().toISOString(),
}))

const start = async () => {
  try {
    await app.listen({ port: Number(process.env.PORT) || 4000, host: '0.0.0.0' })
  } catch (err) {
    app.log.error(err)
    process.exit(1)
  }
}

start()