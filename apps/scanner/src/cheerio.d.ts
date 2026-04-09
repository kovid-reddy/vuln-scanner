/**
 * Module augmentation for cheerio v1.2.0.
 *
 * cheerio v1.2.0's CJS type index (dist/commonjs/index.d.ts) re-exports via
 * `export * from '.js'` which TypeScript's CommonJS module resolver cannot
 * follow, so `load` (and the entire core API) is missing from the type system.
 * This augmentation adds `load` so the build can proceed.
 */
declare module 'cheerio' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type AnyNode = any

  interface CheerioStatic {
    (selector: string | AnyNode): CheerioObject
    (selector: string, context: string | AnyNode | null, root?: string): CheerioObject
    text(): string
  }

  interface CheerioObject {
    each(fn: (index: number, element: AnyNode) => void | boolean): this
    attr(name: string): string | undefined
    attr(name: string, value: string): this
    find(selector: string): CheerioObject
    first(): CheerioObject
    text(): string
    length: number
  }

  function load(
    content: string | Buffer | AnyNode | AnyNode[],
    options?: object | null,
    isDocument?: boolean,
  ): CheerioStatic
}
