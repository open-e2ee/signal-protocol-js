/**
 * Client adapter for app-owned Convex functions backed by `@convex-dev/r2`.
 *
 * The Convex component remains inside the application backend. This module
 * only calls the authenticated wrapper functions supplied in `api`.
 */
import { ConvexR2ObjectStore, type ConvexR2ObjectStoreConfig } from './storage';

export {
  ConvexR2ObjectStore,
  type ConvexObjectStoreClient,
  type ConvexR2ObjectStoreApi,
  type ConvexR2ObjectStoreConfig,
} from './storage';

/** Create a Convex-backed R2 remote object-store adapter. */
export function convexR2ObjectStore(config: ConvexR2ObjectStoreConfig): ConvexR2ObjectStore {
  return new ConvexR2ObjectStore(config);
}
