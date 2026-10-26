import { EncryptionError, EncryptionErrorCode } from '../../../../types/errors';
import { SQLITE_CONVERT_SUFFIX } from '../file-name';

/**
 * A conservative ASCII component budget for portable directory names.
 * Windows documents 255 as the common filesystem component limit:
 * https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
 * This is a portability contract, not a universal OPFS specification limit.
 */
const COMPONENT_MAX_BYTES = 255;
/** The vendored SAH pool's HEADER_MAX_PATH_SIZE, including its terminator reserve. */
const SAH_PATH_HEADER_BYTES = 512;
/**
 * SQLite may append '-' and at most 11 ASCII bytes to a VFS filename:
 * https://sqlite.org/c3ref/vfs.html
 */
const SQLITE_AUXILIARY_SUFFIX_MAX_BYTES = 12;
const POOL_PREFIX = 'open-e2ee-sqlite-';
const POOL_DIRECTORY_PREFIX = `.${POOL_PREFIX}`;
const ROOT_PREFIX = '/';
const encoder = new TextEncoder();

/**
 * The directory is `.<pool prefix><file>`. The SAH header stores `/<file>`
 * and rejects encodedBytes + 1 >= 512. Reserve the root slash, SQLite's
 * auxiliary suffix, the terminator, and the strict-boundary byte. The
 * directory component is the tighter bound: 255 - 18 = 237 bytes.
 */
export const WEB_SQLITE_FILE_NAME_MAX_BYTES = Math.min(
  COMPONENT_MAX_BYTES - encoder.encode(POOL_DIRECTORY_PREFIX).byteLength,
  SAH_PATH_HEADER_BYTES - encoder.encode(ROOT_PREFIX).byteLength - SQLITE_AUXILIARY_SUFFIX_MAX_BYTES - 2
);

/** Every accepted database name also fits its 13-byte conversion ending. */
export const WEB_SQLITE_DATABASE_NAME_MAX_BYTES =
  WEB_SQLITE_FILE_NAME_MAX_BYTES - encoder.encode(SQLITE_CONVERT_SUFFIX).byteLength;

const PATH_SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** A fixed buffer bounds encoding work and allocation for untrusted names. */
const nameBytes = new Uint8Array(WEB_SQLITE_FILE_NAME_MAX_BYTES + 1);

function invalid(message: string, operation: string): never {
  throw new EncryptionError(message, EncryptionErrorCode.INVALID_STATE, { operation });
}

function assertName(name: string, maximum: number, operation: string): void {
  // UTF-8 needs at least as many bytes as UTF-16 code units. Refuse large
  // inputs before encoding, matching a regular expression, or reflecting them.
  if (typeof name !== 'string' || name.length > maximum) {
    invalid(`A Web SQLite file name exceeds the ${maximum}-byte UTF-8 budget.`, operation);
  }
  const { read, written } = encoder.encodeInto(name, nameBytes);
  if (read !== name.length || written > maximum) {
    invalid(`A Web SQLite file name exceeds the ${maximum}-byte UTF-8 budget.`, operation);
  }
  if (!PATH_SAFE_NAME.test(name)) {
    invalid(
      'A Web SQLite file name must start with a letter or digit and contain only letters, digits, dots, dashes, or underscores.',
      operation
    );
  }
}

/** Check a public database name before any lock, vault, worker, or OPFS access. */
export function assertWebSqliteDatabaseName(name: string, operation: string): void {
  assertName(name, WEB_SQLITE_DATABASE_NAME_MAX_BYTES, operation);
  if (name.endsWith(SQLITE_CONVERT_SUFFIX)) {
    invalid('The Web SQLite file name ending is reserved for a conversion temporary file.', operation);
  }
}

/** Check an actual worker filename, including a conversion temporary file. */
export function assertWebSqliteFileName(name: string, operation: string): void {
  assertName(name, WEB_SQLITE_FILE_NAME_MAX_BYTES, operation);
}

/** Stable storage and coordination identities for an already validated filename. */
export function webSqliteFileIdentity(name: string) {
  const poolName = `${POOL_PREFIX}${name}`;
  return {
    path: `${ROOT_PREFIX}${name}`,
    lockName: `open-e2ee:sqlite:${name}`,
    poolName,
    poolDirectory: `.${poolName}`,
    vfsName: `multipleciphers-${poolName}`,
  };
}
