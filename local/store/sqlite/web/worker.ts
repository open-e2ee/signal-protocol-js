/**
 * The dedicated module worker of the web SQLite driver.
 *
 * The worker loads the SQLite3 Multiple Ciphers Wasm engine and keeps each
 * database file in its own `opfs-sahpool` pool, wrapped by the Multiple
 * Ciphers VFS. It runs every statement for the driver in `./driver.ts`.
 *
 * A pool allows one connection, so the tabs of an origin share each file
 * through one Web Lock, `open-e2ee:sqlite:<file>`:
 *
 * - The worker holds the pool attached, and the physical connection open,
 *   exactly while it holds the lock.
 * - A worker that needs the file and does not hold the lock posts a request
 *   on the `BroadcastChannel` of the same name, then waits for the lock.
 * - On a request, the holder finishes its current statement. At the next
 *   autocommit boundary it closes the connection, pauses the pool, and
 *   releases the lock. A transaction never moves to another tab.
 * - The next holder attaches the pool and reopens the connection. It applies
 *   the key and the saved `foreign_keys` value again, and checks that
 *   `user_version` did not change while it was detached.
 *
 * Each request checks, in this order: the file name, the OPFS APIs, one
 * access handle on a new probe file, and then the engine. So a context
 * without OPFS reports `OPFS_UNAVAILABLE` and never downloads the Wasm, also
 * when its CSP refuses the engine.
 *
 * A failure to attach the pool never changes the database file. The vendored
 * engine carries patches that keep the pool directory when its install fails
 * and that release every access handle when an attach fails; see
 * `./sqlite3mc/README.md`. A full origin quota can stop the install of a new
 * pool before it has all its slot files. The attach then fails with
 * `STORAGE_QUOTA_EXCEEDED`, and the next attach adds slot files up to the
 * two that an open needs.
 *
 * The logical connection that the driver returns stays pinned to its file
 * across these physical reopens.
 */

import sqlite3InitModule, {
  type OpfsSahPoolUtil,
  type Sqlite3Database,
  type Sqlite3Static,
} from './sqlite3mc/sqlite3.mjs';
import { generateRandomBytesSync } from '../../../../internal/crypto/random';
import { EncryptionError, EncryptionErrorCode } from '../../../../types/errors';
import type { SqliteRow, SqliteStatementResult, SqliteValue } from '../driver';
import type {
  WireError,
  WorkerConfiguration,
  WorkerRequest,
  WorkerResponse,
  WorkerValue,
} from './protocol';

interface WorkerScope {
  postMessage(message: WorkerResponse): void;
  addEventListener(
    type: 'message',
    listener: (event: MessageEvent<WorkerConfiguration | WorkerRequest>) => void
  ): void;
}

/** A file name is one path segment, so it cannot name another pool. */
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const KEY_LENGTH = 32;
/** Multiple Ciphers reads `raw:` and 32 bytes as a raw key, with no key derivation. */
const RAW_KEY_PREFIX = new Uint8Array([0x72, 0x61, 0x77, 0x3a]);
/** The pool keeps its slot files in this subdirectory of its directory. */
const POOL_SLOT_DIRECTORY = '.opaque';
/**
 * The slot files that an open needs: the database file and its rollback
 * journal. The core keeps the default rollback journal and attaches no other
 * database, so SQLite opens no super-journal. The engine is built with
 * `SQLITE_TEMP_STORE=2` and the core never sets `PRAGMA temp_store`, so
 * temporary files and statement journals stay in memory.
 *
 * The engine adds its six slot files only to a pool that has none, so a pool
 * that a full quota stopped at one slot file has no slot for the journal.
 * Each attach adds slot files up to this minimum and no further: in Chromium,
 * each slot file that the pool writes holds about 1 MiB of quota while the
 * pool is attached, so more slot files under a full quota leave no room for
 * the writes of the database.
 */
const MIN_POOL_CAPACITY = 2;
/**
 * After a tab dies, the browser can release its lock before its access
 * handles. The next holder waits this long for the handles.
 */
const HANDLE_WAIT_MS = 5_000;
const HANDLE_RETRY_MS = 50;

/** One logical connection. It outlives each physical reopen. */
interface Connection {
  readonly id: number;
  /** The worker's copy of the key. `close` zeroes it. */
  readonly key: Uint8Array | null;
  /** Read at detach, applied again at reattach. */
  foreignKeys: number | null;
  /** Read at detach, compared at reattach. `null` when the read failed. */
  userVersion: number | null;
}

/** The state of one database file in this worker. */
interface Slot {
  readonly path: string;
  readonly lockName: string;
  readonly poolName: string;
  readonly poolDirectory: string;
  readonly vfsName: string;
  readonly channel: BroadcastChannel;
  pool: OpfsSahPoolUtil | null;
  /** Releases the Web Lock. Set exactly while this worker holds it. */
  release: (() => void) | null;
  /** Another context waits for the lock. */
  requested: boolean;
  /** The tail of the operation queue of this slot. */
  tail: Promise<void>;
  connection: Connection | null;
  /** The physical connection. Open only while this worker holds the lock. */
  database: Sqlite3Database | null;
}

const scope = globalThis as unknown as WorkerScope;
const engineConfiguration = globalThis as { sqlite3ApiConfig?: unknown };
const slots = new Map<string, Slot>();
/** Multiple Ciphers VFSes that this worker created, by pool name. */
const encryptingVfses = new Set<string>();
let wasmUrl: string | null = null;
let engine: Promise<Sqlite3Static> | null = null;
/** This context created an access handle on a new OPFS file. */
let opfsUsable = false;

function invalidState(message: string, operation: string): EncryptionError {
  return new EncryptionError(message, EncryptionErrorCode.INVALID_STATE, { operation });
}

function detail(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}

function engineUnavailable(error: unknown): EncryptionError {
  return new EncryptionError(
    'The SQLite Wasm engine did not load in its worker. The Content Security Policy ' +
      "of the worker script must allow 'wasm-unsafe-eval' in script-src, and the " +
      `server must send sqlite3.wasm as application/wasm. Cause: ${detail(error)}`,
    EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE,
    { operation: 'loadEngine' }
  );
}

function opfsUnavailable(cause: string): EncryptionError {
  return new EncryptionError(
    `This browser context cannot keep a SQLite database in the origin private file system: ${cause}`,
    EncryptionErrorCode.OPFS_UNAVAILABLE,
    { operation: 'attachPool' }
  );
}

/**
 * A write that exhausts the origin's storage quota fails with
 * QuotaExceededError. Checked by name: engines differ on the constructor.
 */
function isQuotaExceededError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'QuotaExceededError'
  );
}

function quotaExceeded(cause: string): EncryptionError {
  return new EncryptionError(
    `The origin storage quota is full, so the SQLite pool could not prepare its files. ` +
      `No database file changed. Free space and open again. Cause: ${cause}`,
    EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED,
    { operation: 'attachPool' }
  );
}

function fileBusy(cause: string): EncryptionError {
  return new EncryptionError(
    `The SQLite database file could not be opened in the origin private file system this time, ` +
      `and it is unchanged. Retry later. Cause: ${cause}`,
    EncryptionErrorCode.OPFS_FILE_BUSY,
    { operation: 'attachPool' }
  );
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// ===== Engine =====

/**
 * Compiles the Wasm before init. The engine's own loader resolves a promise
 * that never rejects, so without this step a CSP refusal would leave init
 * pending forever. A failed load is not kept: the next call tries again.
 */
function loadEngine(): Promise<Sqlite3Static> {
  engine ??= compileAndInitialize().catch((error: unknown) => {
    engine = null;
    throw error;
  });
  return engine;
}

async function compileAndInitialize(): Promise<Sqlite3Static> {
  if (wasmUrl === null) {
    throw engineUnavailable(new Error('The driver did not configure the Wasm URL'));
  }
  let module: WebAssembly.Module;
  try {
    module = await WebAssembly.compileStreaming(fetch(wasmUrl, { credentials: 'same-origin' }));
  } catch (error) {
    throw engineUnavailable(error);
  }
  let instantiationFailed!: (error: unknown) => void;
  const failure = new Promise<never>((_, reject) => {
    instantiationFailed = reject;
  });
  // A cross-origin isolated context would also install the `opfs` VFS, which
  // starts `sqlite3-opfs-async-proxy.js`. The package does not ship that
  // script, and the driver uses only `opfs-sahpool`. The engine reads this
  // configuration once, at init, and then deletes it.
  engineConfiguration.sqlite3ApiConfig = { disable: { vfs: { opfs: true, 'opfs-vfs': true } } };
  try {
    return await Promise.race([
      sqlite3InitModule({
        instantiateWasm(imports, onSuccess) {
          WebAssembly.instantiate(module, imports).then(
            (instance) => onSuccess(instance, module),
            instantiationFailed
          );
          return {};
        },
      }),
      failure,
    ]);
  } catch (error) {
    throw engineUnavailable(error);
  }
}

// ===== Pool and lock =====

function assertStorageApis(): void {
  const missing: string[] = [];
  if (
    typeof FileSystemFileHandle !== 'function' ||
    !('createSyncAccessHandle' in FileSystemFileHandle.prototype) ||
    typeof navigator.storage?.getDirectory !== 'function'
  ) {
    missing.push('OPFS synchronous access handles');
  }
  if (typeof navigator.locks?.request !== 'function') missing.push('Web Locks');
  if (typeof BroadcastChannel !== 'function') missing.push('BroadcastChannel');
  if (missing.length > 0) throw opfsUnavailable(`missing ${missing.join(', ')}`);
}

function slotFor(file: string, operation: string): Slot {
  if (!FILE_NAME.test(file)) {
    throw invalidState(
      'A SQLite file name must be 1 to 64 letters, digits, dots, dashes, or underscores, and start with a letter or digit',
      operation
    );
  }
  const existing = slots.get(file);
  if (existing !== undefined) return existing;
  assertStorageApis();
  const poolName = `open-e2ee-sqlite-${file}`;
  const slot: Slot = {
    path: `/${file}`,
    lockName: `open-e2ee:sqlite:${file}`,
    poolName,
    poolDirectory: `.${poolName}`,
    vfsName: `multipleciphers-${poolName}`,
    channel: new BroadcastChannel(`open-e2ee:sqlite:${file}`),
    pool: null,
    release: null,
    requested: false,
    tail: Promise.resolve(),
    connection: null,
    database: null,
  };
  slot.channel.onmessage = () => {
    slot.requested = true;
    void enqueue(slot, async () => {
      const sqlite3 = await loadEngine();
      yieldIfRequested(slot, sqlite3);
    }).catch(() => undefined);
  };
  slots.set(file, slot);
  return slot;
}

/** Runs one task at a time for a slot, in call order. */
function enqueue<T>(slot: Slot, task: () => Promise<T>): Promise<T> {
  const run = slot.tail.then(task);
  slot.tail = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

async function acquireLock(slot: Slot): Promise<void> {
  slot.channel.postMessage('request');
  await new Promise<void>((granted, failed) => {
    navigator.locks
      .request(
        slot.lockName,
        () =>
          new Promise<void>((release) => {
            slot.release = release;
            granted();
          })
      )
      .catch(failed);
  });
  // A request posted before this grant reached a context that did not hold
  // the lock. The lock manager still lists the waiter.
  // It only adds a request: `onmessage` can set the flag while the query runs.
  const state = await navigator.locks.query();
  if ((state.pending ?? []).some((lock) => lock.name === slot.lockName)) slot.requested = true;
}

/**
 * Proves once that this context can use OPFS access handles, on a new file
 * that no other context holds. So a later failure is a property of the
 * database file, not of the runtime, such as an ephemeral context that
 * refuses OPFS.
 */
async function assertOpfsUsable(): Promise<void> {
  if (opfsUsable) return;
  const name = `.open-e2ee-sqlite-probe-${Array.from(generateRandomBytesSync(8), (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('')}`;
  try {
    const root = await navigator.storage.getDirectory();
    const file = (await root.getFileHandle(name, { create: true })) as FileSystemFileHandle & {
      createSyncAccessHandle(): Promise<{ close(): void }>;
    };
    try {
      (await file.createSyncAccessHandle()).close();
    } finally {
      await root.removeEntry(name).catch(() => undefined);
    }
  } catch (error) {
    throw opfsUnavailable(detail(error));
  }
  opfsUsable = true;
}

/**
 * Waits until every slot file of the pool accepts a new access handle. After
 * a tab dies, the browser can release its lock before its handles, and the
 * pool cannot attach until the handles are free.
 */
async function waitForFreeHandles(slot: Slot): Promise<void> {
  let slotDirectory: FileSystemDirectoryHandle;
  try {
    const root = await navigator.storage.getDirectory();
    const poolDirectory = await root.getDirectoryHandle(slot.poolDirectory);
    slotDirectory = await poolDirectory.getDirectoryHandle(POOL_SLOT_DIRECTORY);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') return;
    throw fileBusy(detail(error));
  }
  const deadline = Date.now() + HANDLE_WAIT_MS;
  // `FileSystemDirectoryHandle` is async iterable; the DOM library of this
  // build does not declare it.
  const entries = slotDirectory as unknown as AsyncIterable<[string, FileSystemHandle]>;
  for (;;) {
    try {
      for await (const [, handle] of entries) {
        if (handle.kind !== 'file') continue;
        const file = handle as FileSystemFileHandle & {
          createSyncAccessHandle(): Promise<{ close(): void }>;
        };
        (await file.createSyncAccessHandle()).close();
      }
      return;
    } catch (error) {
      if (Date.now() >= deadline) throw fileBusy(detail(error));
      await delay(HANDLE_RETRY_MS);
    }
  }
}

/**
 * Attaches the pool of the slot and adds the slot files that an open needs. A
 * failed attach changes no database file and holds no access handle, so the
 * next call tries again. A full origin quota fails it with
 * `STORAGE_QUOTA_EXCEEDED`, and any other failure with `OPFS_FILE_BUSY`.
 */
async function attachPool(slot: Slot, sqlite3: Sqlite3Static): Promise<void> {
  if (slot.pool !== null && !slot.pool.isPaused()) return;
  await waitForFreeHandles(slot);
  try {
    if (slot.pool === null) {
      slot.pool = await sqlite3.installOpfsSAHPoolVfs({
        name: slot.poolName,
        directory: slot.poolDirectory,
        verbosity: 1,
        forceReinitIfPreviouslyFailed: true,
      });
    } else {
      await slot.pool.unpauseVfs();
    }
    // A failure here leaves the pool attached, and the caller detaches it.
    await slot.pool.reserveMinimumCapacity(MIN_POOL_CAPACITY);
  } catch (error) {
    throw isQuotaExceededError(error) ? quotaExceeded(detail(error)) : fileBusy(detail(error));
  }
  if (!encryptingVfses.has(slot.poolName)) {
    const rc = sqlite3.capi.sqlite3mc_vfs_create(slot.poolName, 0);
    if (rc !== 0) throw new Error(`sqlite3mc_vfs_create: ${sqlite3.capi.sqlite3_js_rc_str(rc)}`);
    encryptingVfses.add(slot.poolName);
  }
}

// ===== Physical connection =====

function applyKey(sqlite3: Sqlite3Static, database: Sqlite3Database, key: Uint8Array): void {
  database.exec("PRAGMA cipher = 'sqlcipher'");
  database.exec('PRAGMA legacy = 4');
  const length = RAW_KEY_PREFIX.length + key.length;
  const pointer = sqlite3.wasm.alloc(length);
  try {
    const heap = sqlite3.wasm.heap8u();
    heap.set(RAW_KEY_PREFIX, pointer);
    heap.set(key, pointer + RAW_KEY_PREFIX.length);
    const rc = sqlite3.capi.sqlite3_key_v2(database.pointer!, 'main', pointer, length);
    if (rc !== 0) throw new Error(sqlite3.capi.sqlite3_errmsg(database.pointer!));
  } finally {
    // The heap view can change when memory grows, so read it again.
    sqlite3.wasm.heap8u().fill(0, pointer, pointer + length);
    sqlite3.wasm.dealloc(pointer);
  }
}

function openPhysical(
  slot: Slot,
  sqlite3: Sqlite3Static,
  flags: 'c' | 'w',
  key: Uint8Array | null
): Sqlite3Database {
  const database = new sqlite3.oo1.DB({ filename: slot.path, flags, vfs: slot.vfsName });
  try {
    if (key !== null) applyKey(sqlite3, database, key);
    // The cipher accepts any key and fails only at the first read. This read
    // rejects a wrong key, a missing key, or a key on a plaintext file with
    // `file is not a database`, before any other setting.
    readValue(database, 'SELECT count(*) FROM sqlite_schema');
  } catch (error) {
    database.close();
    throw error;
  }
  return database;
}

/** The first column of the first row of `sql`, or `undefined` for no row. */
function readValue(database: Sqlite3Database, sql: string): unknown {
  const statement = database.prepare(sql);
  try {
    return statement.step() ? Object.values(statement.get({}))[0] : undefined;
  } finally {
    statement.finalize();
  }
}

function readInteger(database: Sqlite3Database, pragma: string): number {
  const value = readValue(database, `PRAGMA ${pragma}`);
  if (typeof value !== 'number') throw new Error(`PRAGMA ${pragma} returned ${typeof value}`);
  return value;
}

function readIntegerOrNull(database: Sqlite3Database, pragma: string): number | null {
  try {
    return readInteger(database, pragma);
  } catch {
    return null;
  }
}

/** Opens the physical connection again after another context held the file. */
function reopen(slot: Slot, sqlite3: Sqlite3Static, connection: Connection): void {
  if (!slot.pool!.getFileNames().includes(slot.path)) {
    throw invalidState('The database file was removed while another tab held it', 'reopen');
  }
  const database = openPhysical(slot, sqlite3, 'w', connection.key);
  try {
    if (connection.foreignKeys !== null) {
      database.exec(`PRAGMA foreign_keys = ${connection.foreignKeys === 0 ? 'OFF' : 'ON'}`);
    }
    if (connection.userVersion !== null) {
      const userVersion = readInteger(database, 'user_version');
      if (userVersion !== connection.userVersion) {
        throw invalidState(
          `Another tab changed the database schema version from ${connection.userVersion} to ${userVersion}. Close this store and open it again.`,
          'reopen'
        );
      }
    }
  } catch (error) {
    database.close();
    throw error;
  }
  slot.database = database;
}

/** Closes the physical connection, pauses the pool, and releases the lock. */
function detach(slot: Slot): void {
  const database = slot.database;
  if (database !== null) {
    const connection = slot.connection;
    if (connection !== null) {
      connection.foreignKeys = readIntegerOrNull(database, 'foreign_keys');
      connection.userVersion = readIntegerOrNull(database, 'user_version');
    }
    slot.database = null;
    database.close();
  }
  slot.pool?.pauseVfs();
  const release = slot.release;
  slot.release = null;
  slot.requested = false;
  release?.();
}

function atAutocommitBoundary(slot: Slot, sqlite3: Sqlite3Static): boolean {
  return (
    slot.database === null || sqlite3.capi.sqlite3_get_autocommit(slot.database.pointer!) !== 0
  );
}

function yieldIfRequested(slot: Slot, sqlite3: Sqlite3Static): void {
  if (slot.release !== null && slot.requested && atAutocommitBoundary(slot, sqlite3)) {
    detach(slot);
  }
}

/**
 * Runs `operation` while this worker holds the file. The OPFS probe runs
 * before the engine loads; see the order at the top. The worker keeps the
 * lock after the operation only while a connection is open and no other
 * context asked for it, or while a transaction is open.
 */
function withFile<T>(
  slot: Slot,
  operation: (sqlite3: Sqlite3Static) => T
): Promise<T> {
  return enqueue(slot, async () => {
    await assertOpfsUsable();
    const sqlite3 = await loadEngine();
    if (slot.release === null) await acquireLock(slot);
    try {
      await attachPool(slot, sqlite3);
      if (slot.connection !== null && slot.database === null) {
        reopen(slot, sqlite3, slot.connection);
      }
      return operation(sqlite3);
    } finally {
      if (slot.connection === null || slot.database === null) {
        detach(slot);
      } else {
        yieldIfRequested(slot, sqlite3);
      }
    }
  });
}

// ===== Operations =====

function connectionOf(slot: Slot, id: number, operation: string): Connection {
  const connection = slot.connection;
  if (connection === null || connection.id !== id) {
    throw invalidState('The SQLite connection is closed', operation);
  }
  return connection;
}

function toRow(row: Record<string, unknown>): SqliteRow {
  for (const [column, value] of Object.entries(row)) {
    if (typeof value === 'bigint') {
      throw invalidState(`Column ${column} holds an integer outside the safe range`, 'execute');
    }
    if (value !== null && typeof value !== 'string' && typeof value !== 'number') {
      throw invalidState(`Column ${column} holds a value that is not TEXT, INTEGER, REAL, or NULL`, 'execute');
    }
  }
  return row as SqliteRow;
}

/**
 * Rejects SQL that holds more than one statement, as the Node driver does.
 * `prepare` compiles the first statement and ignores the rest, so this
 * compiles each statement of the text and finalizes it at once. Whitespace,
 * comments, and semicolons after the statement are allowed.
 */
function assertOneStatement(sqlite3: Sqlite3Static, database: Sqlite3Database, sql: string): void {
  // A second statement needs a semicolon, and most SQL has none.
  if (!sql.includes(';')) return;
  const { capi, wasm } = sqlite3;
  const [text, length] = wasm.allocCString(sql, true);
  const out = wasm.alloc(2 * wasm.ptr.size);
  const statementOut = out;
  const tailOut = out + wasm.ptr.size;
  const end = text + length;
  try {
    let next = text;
    let statements = 0;
    while (next < end) {
      wasm.pokePtr(statementOut, 0);
      wasm.pokePtr(tailOut, 0);
      const rc = capi.sqlite3_prepare_v3(database.pointer!, next, end - next, 0, statementOut, tailOut);
      const statement = wasm.peekPtr(statementOut);
      if (statement !== 0) {
        capi.sqlite3_finalize(statement);
        statements += 1;
      }
      if (rc !== 0 || statements > 1) {
        throw new RangeError('The supplied SQL string contains more than one statement');
      }
      next = wasm.peekPtr(tailOut);
    }
  } finally {
    wasm.dealloc(out);
    wasm.dealloc(text);
  }
}

function execute(
  sqlite3: Sqlite3Static,
  database: Sqlite3Database,
  sql: string,
  params: readonly SqliteValue[]
): SqliteStatementResult {
  const statement = database.prepare(sql);
  try {
    assertOneStatement(sqlite3, database, sql);
    if (params.length > 0) statement.bind(params);
    const rows: SqliteRow[] = [];
    while (statement.step()) rows.push(toRow(statement.get({})));
    return { rows, changes: database.changes() };
  } finally {
    statement.finalize();
  }
}

async function handle(request: WorkerRequest): Promise<WorkerValue> {
  const slot = slotFor(request.file, request.type);
  switch (request.type) {
    case 'exists':
      return withFile(slot, () => slot.pool!.getFileNames().includes(slot.path));
    case 'remove':
      if (slot.connection !== null) {
        throw invalidState('Close the SQLite connection before removing its file', 'remove');
      }
      return withFile(slot, () => {
        slot.pool!.unlink(slot.path);
        slot.pool!.unlink(`${slot.path}-journal`);
        return undefined;
      });
    case 'open': {
      const key = request.key;
      if (key !== null && key.length !== KEY_LENGTH) {
        throw invalidState(`A SQLite key must be ${KEY_LENGTH} bytes`, 'open');
      }
      if (slot.connection !== null) {
        throw invalidState('This store already has an open connection to the file', 'open');
      }
      return withFile(slot, (sqlite3) => {
        slot.database = openPhysical(slot, sqlite3, 'c', key);
        slot.connection = {
          id: request.connection,
          key,
          foreignKeys: null,
          userVersion: null,
        };
        return undefined;
      });
    }
    case 'execute': {
      connectionOf(slot, request.connection, 'execute');
      return withFile(slot, (sqlite3) => {
        connectionOf(slot, request.connection, 'execute');
        return execute(sqlite3, slot.database!, request.sql, request.params);
      });
    }
    case 'probeCipher': {
      connectionOf(slot, request.connection, 'probeCipher');
      return withFile(slot, () => {
        const database = slot.database!;
        // `PRAGMA cipher` also answers on an unkeyed plaintext database. Only
        // a keyed database has a cipher salt.
        if (readValue(database, "SELECT sqlite3mc_codec_data('cipher_salt')") == null) return null;
        const cipher = readValue(database, 'PRAGMA cipher');
        return typeof cipher === 'string' ? cipher : null;
      });
    }
    case 'close':
      return enqueue(slot, async () => {
        const connection = slot.connection;
        if (connection === null || connection.id !== request.connection) return undefined;
        slot.connection = null;
        connection.key?.fill(0);
        if (slot.release !== null) detach(slot);
        return undefined;
      });
  }
}

function isConnectionKey(key: Uint8Array): boolean {
  for (const slot of slots.values()) {
    if (slot.connection?.key === key) return true;
  }
  return false;
}

function toWireError(error: unknown): WireError {
  if (error instanceof EncryptionError) {
    switch (error.code) {
      case EncryptionErrorCode.INVALID_STATE:
      case EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE:
      case EncryptionErrorCode.OPFS_UNAVAILABLE:
      case EncryptionErrorCode.OPFS_FILE_BUSY:
      case EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED:
        return {
          kind: 'sdk',
          code: error.code,
          message: error.message,
          ...(error.operation === undefined ? {} : { context: { operation: error.operation } }),
        };
    }
  }
  return { kind: 'error', message: error instanceof Error ? error.message : String(error) };
}

scope.addEventListener('message', (event) => {
  const message = event.data;
  if (message.type === 'configure') {
    wasmUrl = message.wasmUrl;
    return;
  }
  handle(message).then(
    (value) => scope.postMessage({ id: message.id, ok: true, value }),
    (error: unknown) => {
      // A key that did not become a connection's key is zeroed at once.
      if (message.type === 'open' && message.key !== null && !isConnectionKey(message.key)) {
        message.key.fill(0);
      }
      scope.postMessage({ id: message.id, ok: false, error: toWireError(error) });
    }
  );
});
