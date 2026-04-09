import { Redis } from 'ioredis'

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