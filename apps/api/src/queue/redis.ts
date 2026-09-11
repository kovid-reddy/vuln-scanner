import { Redis } from 'ioredis'

// In production, REDIS_URL must be set explicitly (injected by Render from the internal Redis service).
// Falling back to localhost is only acceptable for local development.
if (process.env.NODE_ENV === 'production' && !process.env.REDIS_URL) {
  console.error('[redis] FATAL: REDIS_URL is not set in production. Exiting.')
  process.exit(1)
}

export const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: null,
  retryStrategy(times: number) {
    if (times > 10) {
      console.error('[redis] Too many retries — giving up')
      return null
    }
    const delay = Math.min(times * 500, 5000)
    console.log(`[redis] Reconnecting in ${delay}ms (attempt ${times})`)
    return delay
  },
  lazyConnect: false,
})

redis.on('connect',      () => console.log('[redis] Connected'))
redis.on('error',        (err: Error) => console.error('[redis] Error:', err.message))
redis.on('reconnecting', () => console.log('[redis] Reconnecting...'))