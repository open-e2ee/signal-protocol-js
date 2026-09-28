/**
 * The part of the SQLite3 Multiple Ciphers Wasm API that the web worker uses.
 * The engine ships no declarations, so this file declares only that part.
 */

export type WasmPointer = number;

export interface Sqlite3Stmt {
  readonly columnCount: number;
  bind(values: readonly (string | number | null)[]): Sqlite3Stmt;
  step(): boolean;
  get(target: Record<string, unknown>): Record<string, unknown>;
  finalize(): void;
}

export interface Sqlite3Database {
  readonly pointer: WasmPointer | undefined;
  prepare(sql: string): Sqlite3Stmt;
  exec(sql: string): Sqlite3Database;
  changes(): number;
  close(): void;
}

export interface Sqlite3DatabaseOptions {
  filename: string;
  /** `c` creates the file, `w` opens it read-write. */
  flags: string;
  vfs: string;
}

export interface OpfsSahPoolUtil {
  getFileNames(): string[];
  unlink(name: string): boolean;
  pauseVfs(): OpfsSahPoolUtil;
  unpauseVfs(): Promise<OpfsSahPoolUtil>;
  isPaused(): boolean;
}

export interface OpfsSahPoolOptions {
  name: string;
  directory?: string;
  initialCapacity?: number;
  clearOnInit?: boolean;
  verbosity?: 0 | 1 | 2 | 3;
  forceReinitIfPreviouslyFailed?: boolean;
}

export interface Sqlite3Static {
  readonly oo1: {
    DB: new (options: Sqlite3DatabaseOptions) => Sqlite3Database;
  };
  readonly capi: {
    sqlite3_get_autocommit(db: WasmPointer): number;
    sqlite3_key_v2(db: WasmPointer, schema: string, key: WasmPointer, length: number): number;
    sqlite3_errmsg(db: WasmPointer): string;
    sqlite3_prepare_v3(
      db: WasmPointer,
      sql: WasmPointer,
      length: number,
      flags: number,
      statementOut: WasmPointer,
      tailOut: WasmPointer
    ): number;
    sqlite3_finalize(statement: WasmPointer): number;
    sqlite3mc_vfs_create(baseVfs: string, makeDefault: number): number;
    sqlite3_js_rc_str(rc: number): string;
  };
  readonly wasm: {
    alloc(length: number): WasmPointer;
    dealloc(pointer: WasmPointer): void;
    heap8u(): Uint8Array;
    /** With `true`, returns the pointer and the UTF-8 length without the NUL. */
    allocCString(text: string, withLength: true): [WasmPointer, number];
    readonly ptr: { readonly size: number };
    peekPtr(pointer: WasmPointer): WasmPointer;
    pokePtr(pointer: WasmPointer, value: WasmPointer): void;
  };
  installOpfsSAHPoolVfs(options: OpfsSahPoolOptions): Promise<OpfsSahPoolUtil>;
}

export interface Sqlite3InitOptions {
  instantiateWasm(
    imports: WebAssembly.Imports,
    onSuccess: (instance: WebAssembly.Instance, module: WebAssembly.Module) => void
  ): Record<string, never>;
}

export default function sqlite3InitModule(options: Sqlite3InitOptions): Promise<Sqlite3Static>;
