import 'dotenv/config'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import { scanRoutes } from './routes/scan.routes'

const app = Fastify({ logger: { level: 'info' } })

app.register(cors, {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
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