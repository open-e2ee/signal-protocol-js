/**
 * Signal Protocol Manager Module
 *
 * @layer 2 - Orchestration
 * @implements ISignalProtocolManager
 *
 * High-level orchestrator for Signal Protocol operations:
 * - Identity key management and initialization
 * - PreKey bundle generation and rotation
 * - Session establishment (X3DH/PQXDH)
 * - Message encryption/decryption (via Double Ratchet)
 * - Triple Ratchet (SPQR) integration for post-quantum security
 */
export {};
export { SignalProtocolManager } from './manager';
