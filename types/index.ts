/**
 * Type definitions for Signal Protocol end-to-end encryption
 *
 * Exposes stable public contracts for addresses, trust, sessions, messages,
 * storage, clients, and protocol policy.
 *
 * See docs/E2EE.md for implementation details
 */

export {};
export * from './address';

// Composite-identity trust verification
export * from './trust';

// Session contracts
export * from './session';

// Message contracts
export * from './messages';

// API interfaces
export * from './api';

// Client configuration
// Import directly: import { SignalProtocolClientConfig, ILogger, ProgressCallback } from './client/config'

// Error types (enhanced with specialized error classes)
export * from './errors';

// Event hooks - MOVED to ../client/hooks.ts (colocated with SignalProtocolClient)
// Import directly: import { SignalProtocolClientHooks, callHook } from './client/hooks'

// Utility types
export * from './utils';

// SESAME multi-device session management
// Re-export from canonical location in sesame/types.ts
export * from '../internal/sesame/types';

// Protocol constants (versioning, device IDs, message limits)
export * from './protocol-constants';

// Protocol strategy configuration and profile constants
export * from './protocol-config';
