/**
 * The listing of metadata keys by prefix, which the optional
 * `listMetadataKeys` of a store gives. The order compares keys by UTF-16
 * code unit, as JavaScript string comparison does.
 */
import type { MetadataKeyQuery } from '../../types/api';

/** The default page size of a metadata key listing. */
export const METADATA_KEY_DEFAULT_LIMIT = 100;

/** The page size of a query. */
export function metadataKeyLimit(query: MetadataKeyQuery): number {
  const limit = query.limit ?? METADATA_KEY_DEFAULT_LIMIT;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError('limit must be a positive integer');
  }
  return limit;
}

/** Filter, order, and page a set of metadata keys, for a store that scans. */
export function selectMetadataKeys(keys: Iterable<string>, query: MetadataKeyQuery): string[] {
  const limit = metadataKeyLimit(query);
  const { prefix, after } = query;
  return [...keys]
    .filter((key) => key.startsWith(prefix) && (after === undefined || key > after))
    .sort()
    .slice(0, limit);
}
