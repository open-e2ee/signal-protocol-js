/**
 * Message type definitions for Signal Protocol
 */

import type { CompositeIdentityV1, IdentityType, PublicKey } from '../keys';
import type { Base64 } from './utils';

/**
 * Ciphertext message discriminator for exhaustive type checking.
 * Based on Signal Protocol wire format message types.
 *
 */
export {};
export enum MessageType {
  /**
   * Regular Double Ratchet message.
   *
   * Standard encrypted message using the Double Ratchet algorithm.
   * Used after session has been established.
   */
  RATCHET = 'ratchet',

  /**
   * PreKey message for initial session establishment.
   *
   * First message from initiator to responder. Contains extra information
   * needed for responder to establish session using X3DH/PQXDH.
   */
  PREKEY = 'prekey',
}

/**
 * Content hint for message delivery and retry behavior.
 *
 * Numeric values are part of the sealed-sender wire format and must remain
 * synchronized with its protobuf schema.
 *
 * From Signal Protocol:
 * "Content hints allow the client to make informed decisions about
 * message resendability and storage without decrypting the message."
 *
 */
export enum ContentHint {
  /**
   * Default behavior - no special handling.
   *
   * Message is treated as a normal user message with standard
   * retry and storage policies.
   */
  Default = 0,

  /**
   * Message can be safely resent if delivery fails.
   *
   * Examples:
   * - Text messages
   * - Media with permanent URLs
   * - Messages that aren't time-sensitive
   *
   * Resendable messages can be retried multiple times with exponential
   * backoff if delivery fails.
   */
  Resendable = 1,

  /**
   * Implicit/ephemeral message - don't store long-term.
   *
   * Examples:
   * - Typing indicators
   * - Read receipts
   * - Delivery receipts
   * - Presence updates
   *
   * Implicit messages:
   * - Should not be resent if delivery fails
   * - Can be discarded to save storage space
   * - Have lower priority in delivery queue
   * - Don't contribute to unread counts
   */
  Implicit = 2,
}

/**
 * Double Ratchet message header
 *
 * Contains metadata needed for DH ratcheting and out-of-order message handling.
 * This header is sent with every encrypted message.
 *
 * Field names reflect the SignalProtocolMessage wire fields:
 */
export interface MessageHeader {
  /**
   * Sender's current ratchet public key (proto: ratchet_key, field 1).
   *
   * This is the ephemeral DH public key used in the Double Ratchet algorithm.
   * When this changes, the recipient performs a DH ratchet step.
   */
  ratchetKey: PublicKey;

  /**
   * Message counter within the current sending chain (proto: counter, field 2).
   *
   * Increments with each message sent. Used for:
   * - Deriving message keys from the chain key
   * - Detecting out-of-order and missing messages
   * - Indexing skipped message keys in MKSKIPPED
   */
  counter: number;

  /**
   * Number of messages in the previous sending chain (proto: previous_counter, field 3).
   *
   * When a DH ratchet occurs, this tells the recipient how many messages
   * were sent in the previous chain, allowing them to store skipped keys.
   */
  previousCounter: number;
}

/**
 * Complete encrypted message with Double Ratchet header
 *
 * This is the wire format for messages using the full Double Ratchet.
 * Uses AES-256-CBC + HMAC-SHA256 per Signal Protocol specification.
 *
 * Section 3 Variant (Plaintext Headers + MAC):
 * - DH public key is sent in plaintext (needed to determine key chain)
 * - Message counters are sent in plaintext (PN and N)
 * - HMAC-SHA256 (truncated to 8 bytes) authenticates header + ciphertext
 * - Identity keys are included in MAC computation for session binding
 *
 * @see https://signal.org/docs/specifications/doubleratchet/ (Section 3)
 */
export interface RatchetMessage {
  /** Message type discriminator - enables exhaustive type checking */
  type: MessageType.RATCHET;

  /**
   * Wire format version for protocol evolution.
   *
   * Format 'v1' (current): JSON serialization, plaintext headers + identity-bound MAC
   *
   * Allows backward/forward compatibility - recipients can gracefully handle
   * different versions or reject unsupported versions during decryption.
   *
   */
  messageVersion: string;

  /** Sender's current ratchet public key (proto: ratchet_key, field 1) */
  ratchetKey: PublicKey;
  /** Message counter in current sending chain (proto: counter, field 2) */
  counter: number;
  /** Number of messages in previous sending chain (proto: previous_counter, field 3) */
  previousCounter: number;
  /** AES-CBC encrypted message body */
  ciphertext: Base64;
  /** HMAC-SHA256 truncated to 8 bytes (identity-bound: includes sender/receiver identity keys) */
  mac: Base64;

  // Note: SPQR fields (epoch, messageNumber, kyberCiphertext, kyberPublicKey, versionCapability)
  // are opaque bytes in SignalProtocolMessage protobuf field 5 (pqRatchet). The cipher layer never
  // unpacks them — spqrSend/spqrRecv handle all SPQR internals as a black box.

  /**
   * Content hint for delivery and retry behavior (optional).
   *
   * Helps optimize message handling without decrypting:
   * - DEFAULT: Normal message with standard policies
   * - RESENDABLE: Can be retried if delivery fails
   * - IMPLICIT: Ephemeral (typing, receipts) - don't store long-term
   */
  contentHint?: ContentHint;
}

/**
 * PreKey message for initial session establishment.
 *
 * The first message from Alice to Bob contains additional information needed
 * for Bob to establish his session as the responder. This follows the
 * Signal Protocol specification for asynchronous messaging.
 *
 * Per X3DH spec: "Alice sends Bob an initial message containing:
 * - Alice's identity key IKA
 * - Alice's ephemeral key EKA
 * - Ciphertext encrypted with shared secret SK"
 *
 * This allows Bob to:
 * 1. Extract Alice's keys from the message
 * 2. Perform X3DH as responder using Alice's ephemeral key
 * 3. Derive the same shared secret SK
 * 4. Decrypt the message and establish his session
 */
export interface PreKeyMessage {
  /** Message type discriminator - enables exhaustive type checking */
  type: MessageType.PREKEY;

  /**
   * Wire format version for protocol evolution.
   *
   * Format 'v1' (current): JSON serialization, plaintext headers + identity-bound MAC
   *
   * Allows backward/forward compatibility - recipients can gracefully handle
   * different versions or reject unsupported versions during decryption.
   *
   */
  messageVersion: string;

  // RatchetMessage fields (not extending to avoid type conflict)
  /** Sender's current ratchet public key (proto: ratchet_key, field 1) */
  ratchetKey: PublicKey;
  /** Message counter in current sending chain (proto: counter, field 2) */
  counter: number;
  /** Number of messages in previous sending chain (proto: previous_counter, field 3) */
  previousCounter: number;
  /** AES-CBC encrypted message body */
  ciphertext: Base64;
  /** HMAC-SHA256 truncated to 8 bytes (identity-bound: includes sender/receiver identity keys) */
  mac: Base64;

  // PreKey-specific fields
  senderId: string; // Sender's user ID (needed for responder to establish session)
  senderDeviceId: number; // Sender's device ID (required for multi-device SESAME)
  senderIdentity: CompositeIdentityV1; // Sender's canonical composite identity
  senderEphemeralKey: PublicKey; // Sender's ephemeral DH public key - critical for responder X3DH
  senderRegistrationId: number; // Sender's registration ID (for session reset detection)
  /** Explicit recipient account identity namespace, authenticated by the inner message MAC. */
  recipientIdentityType: IdentityType;
  usedSignedPreKeyId?: number; // ID of recipient's signed prekey used (for one-time prekey removal)
  usedOneTimePreKeyId?: number; // ID of recipient's one-time prekey used (if available)

  // PQXDH (Post-Quantum Extended Diffie-Hellman) fields
  usedKyberPreKeyId?: number; // ID of recipient's Kyber last-resort prekey used
  kyberCiphertext?: Base64; // ML-KEM-1024 ciphertext for last-resort prekey
  usedKemOneTimePreKeyId?: number; // ID of recipient's one-time KEM prekey used
  kemOneTimePreKeyCiphertext?: Base64; // ML-KEM-1024 ciphertext for one-time prekey
}

/**
 * Union type for all encrypted message types.
 *
 * Enables exhaustive type checking with TypeScript's discriminated unions.
 *
 * @example
 * ```typescript
 * function processMessage(message: ProtocolMessage) {
 *   switch (message.type) {
 *     case MessageType.RATCHET:
 *       // TypeScript knows this is RatchetMessage
 *       return handleRatchetMessage(message);
 *     case MessageType.PREKEY:
 *       // TypeScript knows this is PreKeyMessage
 *       return handlePreKeyMessage(message);
 *     default:
 *       // Exhaustiveness check - will error if we add new types
 *       const _exhaustive: never = message;
 *       throw new Error('Unknown message type');
 *   }
 * }
 * ```
 */
export type ProtocolMessage = RatchetMessage | PreKeyMessage;

/**
 * Type guard for PreKeyMessage.
 *
 * @param message - Message to check
 * @returns true if message is a PreKeyMessage
 *
 * @example
 * ```typescript
 * if (isPreKeyMessage(message)) {
 *   // TypeScript knows message is PreKeyMessage here
 *   console.log(message.senderIdentity);
 * }
 * ```
 */
export function isPreKeyMessage(message: ProtocolMessage): message is PreKeyMessage {
  return message.type === MessageType.PREKEY;
}

/**
 * Type guard for RatchetMessage.
 *
 * @param message - Message to check
 * @returns true if message is a RatchetMessage
 */
export function isRatchetMessage(message: ProtocolMessage): message is RatchetMessage {
  return message.type === MessageType.RATCHET;
}
