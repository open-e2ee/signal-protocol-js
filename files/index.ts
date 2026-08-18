/**
 * Attachment and encrypted file helpers
 *
 * This module exposes the stable file-transfer primitives that real app
 * integrations need when they own download, cache, and local file lifecycle.
 *
 * Use this alongside `SignalProtocolRemoteObjectStore` implementations for the common
 * two-layer attachment flow:
 * 1. Encrypt file bytes with streaming AEAD
 * 2. Upload ciphertext through the remote object store
 * 3. Exchange metadata and keys through Signal Protocol
 * 4. Download and decrypt ciphertext locally
 */

export {};
export {
  streamingEncrypt,
  streamingDecrypt,
  DEFAULT_SEGMENT_SIZE,
  secureZeroBytes,
} from '../internal/crypto';
