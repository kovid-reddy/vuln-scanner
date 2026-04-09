/**
 * Module augmentation for bullmq v5.
 *
 * bullmq v5's ESM type index file (dist/esm/index.d.ts) contains only
 * `export * from '.js'` entries which TypeScript's CommonJS module resolver
 * cannot follow, resulting in zero exported members. This file adds the
 * core classes this codebase needs so the build passes with full types.
 */
declare module 'bullmq' {
  interface QueueOptions {
    connection: unknown
    prefix?: string
    [key: string]: unknown
  }

  interface WorkerOptions {
    connection: unknown
    concurrency?: number
    lockDuration?: number
    [key: string]: unknown
  }

  interface JobOptions {
    attempts?: number
    backoff?: { type: string; delay: number }
    delay?: number
    priority?: number
    removeOnComplete?: boolean | number
    removeOnFail?: boolean | number
    [key: string]: unknown
  }

  export class Job<DataType = unknown, ReturnType = unknown> {
    id?: string
    name: string
    data: DataType
    returnvalue: ReturnType
    attemptsMade: number
    timestamp: number
    processedOn?: number
    finishedOn?: number
  }

  export class Queue<DataType = unknown> {
    name: string
    constructor(name: string, opts: QueueOptions)
    add(name: string, data: DataType, opts?: JobOptions): Promise<Job<DataType>>
    close(): Promise<void>
    getJob(jobId: string): Promise<Job<DataType> | undefined>
  }

  export class Worker<DataType = unknown, ReturnType = unknown> {
    name: string
    constructor(
      name: string,
      processor: (job: Job<DataType>) => Promise<ReturnType>,
      opts: WorkerOptions,
    )
    on(event: 'failed',    handler: (job: Job<DataType> | undefined, err: Error) => void): this
    on(event: 'completed', handler: (job: Job<DataType>, result: ReturnType) => void): this
    on(event: string,      handler: (...args: unknown[]) => void): this
    close(): Promise<void>
  }
}
