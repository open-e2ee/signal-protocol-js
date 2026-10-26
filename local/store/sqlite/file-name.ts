/** The core reserves this ending for a plaintext conversion's temporary file. */
export const SQLITE_CONVERT_SUFFIX = '.oe2e-convert';

/** The temporary file of the conversion of the store `name`. */
export function sqliteConvertTempName(name: string): string {
  return `${name}${SQLITE_CONVERT_SUFFIX}`;
}
