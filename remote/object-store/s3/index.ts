/**
 * Framework-neutral client adapter for brokered, presigned S3 operations.
 */
import { S3ObjectStore, type S3ObjectStoreConfig } from './storage';

export { S3ObjectStore, type S3ObjectStoreBroker, type S3ObjectStoreConfig } from './storage';

/** Create a brokered S3 remote object-store adapter. */
export function s3ObjectStore(config: S3ObjectStoreConfig): S3ObjectStore {
  return new S3ObjectStore(config);
}
