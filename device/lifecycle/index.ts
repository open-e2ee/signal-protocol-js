/**
 * Device Lifecycle Module
 *
 * Manages device registration, stale detection, and re-registration.
 * Extracted from host lifecycle for testability.
 *
 * @example
 * ```typescript
 * import { DeviceLifecycleManager } from './';
 *
 * const manager = new DeviceLifecycleManager(userId, {
 *   secureStore,
 *   convex,
 *   keyStorage,
 *   logger,
 * });
 *
 * const result = await manager.initialize();
 * ```
 */
export {};
export { DeviceLifecycleManager } from './manager';
export { getLocalDeviceMetadata, getMissingMetadata } from './utils';

export type {
  // Dependency interfaces
  ISecureStore,
  IConvexClient,
  DeviceLifecycleApi,
  IKeyStorageOps,
  ILogger,
  DeviceLifecycleDeps,
  // Device info
  DeviceInfo,
  DeviceMetadata,
  // Results
  InitializationResult,
  StaleCheckResult,
  RegistrationResult,
  // Progress
  RegistrationStage,
  RegistrationProgress,
  OnProgress,
  // Options
  RegisterDeviceOptions,
  HandleStaleDeviceOptions,
  // State machine types (new)
  DeviceChoice,
  DeviceRegistrationState,
  VerifiedInitializationResult,
  ActionResult,
} from './types';
