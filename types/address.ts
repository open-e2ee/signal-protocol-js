/**
 * address.ts
 *
 * Protocol address types for identifying devices in the Signal Protocol.
 * Provides ProtocolAddress for structured device addressing.
 *
 * In the Signal Protocol, each device is uniquely identified by a combination
 * of userId and deviceId. This allows proper multi-device support and prevents
 * bugs from treating addresses as opaque strings.
 *
 */

/**
 * Represents a unique device address in the Signal Protocol.
 *
 * Format: userId:deviceId (e.g., "user123:1")
 *
 * This follows the Signal Protocol convention where SignalProtocolAddress.toString()
 * returns "name:deviceId". See: https://signal.org/docs/
 *
 * @example
 * ```typescript
 * const address = ProtocolAddress.create('user123', 1);
 * console.log(ProtocolAddress.toString(address)); // "user123:1"
 *
 * const parsed = ProtocolAddress.parse('user456:2');
 * console.log(parsed.userId);   // "user456"
 * console.log(parsed.deviceId); // 2
 * ```
 */
export {};
export interface ProtocolAddress {
  /** User identifier (UUID, username, or application-specific ID) */
  readonly userId: string;

  /** Device identifier (unique per user, typically 1 for primary device) */
  readonly deviceId: number;
}

/**
 * Utility functions for working with ProtocolAddress.
 *
 * These functions provide safe creation, parsing, and serialization
 * of protocol addresses while maintaining type safety.
 */
export namespace ProtocolAddress {
  // ==========================================================================
  // Internal Validation Helpers
  // ==========================================================================

  /**
   * Validate userId and deviceId components.
   *
   * Used internally by create(), parse(), and isValid() to avoid duplication.
   *
   * @param userId - User identifier to validate
   * @param deviceId - Device identifier to validate
   * @returns Error message if invalid, null if valid
   */
  function validateComponents(userId: string | undefined, deviceId: number): string | null {
    if (!userId || userId.trim().length === 0) {
      return 'userId cannot be empty';
    }
    if (!Number.isInteger(deviceId) || deviceId < 0) {
      return 'deviceId must be a non-negative integer';
    }
    return null;
  }

  /**
   * Try to parse an address string without throwing.
   *
   * Used internally for validation without exception overhead.
   *
   * @param address - String address to parse
   * @returns { userId, deviceId, error } with error being null if valid
   */
  function tryParse(address: string): { userId?: string; deviceId?: number; error: string | null } {
    const parts = address.split(':');
    if (parts.length !== 2) {
      return { error: `Invalid address format: expected "userId:deviceId"` };
    }

    const [userId, deviceIdStr] = parts;
    const deviceId = parseInt(deviceIdStr ?? '', 10);

    if (isNaN(deviceId)) {
      return { error: `Invalid deviceId: "${deviceIdStr}"` };
    }

    const validationError = validateComponents(userId, deviceId);
    if (validationError) {
      return { error: validationError };
    }

    return { userId, deviceId, error: null };
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  /**
   * Create a new ProtocolAddress.
   *
   * @param userId - User identifier
   * @param deviceId - Device identifier (must be non-negative)
   * @returns A new ProtocolAddress
   * @throws {Error} If userId is empty or deviceId is negative
   *
   * @example
   * ```typescript
   * const address = ProtocolAddress.create('user123', 1);
   * ```
   */
  export function create(userId: string, deviceId: number): ProtocolAddress {
    const error = validateComponents(userId, deviceId);
    if (error) {
      throw new Error(error);
    }
    return { userId, deviceId };
  }

  /**
   * Parse a string address into a ProtocolAddress.
   *
   * Expected format: "userId:deviceId" (Signal Protocol standard)
   *
   * @param address - String address in "userId:deviceId" format
   * @returns Parsed ProtocolAddress
   * @throws {Error} If address format is invalid
   *
   * @example
   * ```typescript
   * const address = ProtocolAddress.parse('user123:1');
   * // { userId: 'user123', deviceId: 1 }
   *
   * ProtocolAddress.parse('invalid');
   * // Error: Invalid address format
   * ```
   */
  export function parse(address: string): ProtocolAddress {
    const result = tryParse(address);
    if (result.error) {
      throw new Error(result.error);
    }
    return { userId: result.userId!, deviceId: result.deviceId! };
  }

  /**
   * Convert a ProtocolAddress to string format.
   *
   * Uses Signal Protocol standard format: "userId:deviceId"
   *
   * @param address - The address to serialize
   * @returns String representation "userId:deviceId"
   *
   * @example
   * ```typescript
   * const address = ProtocolAddress.create('user123', 1);
   * ProtocolAddress.toString(address); // "user123:1"
   * ```
   */
  export function toString(address: ProtocolAddress): string {
    return `${address.userId}:${address.deviceId}`;
  }

  /**
   * Check if two addresses are equal.
   *
   * @param a - First address
   * @param b - Second address
   * @returns true if addresses are equal
   *
   * @example
   * ```typescript
   * const addr1 = ProtocolAddress.create('user123', 1);
   * const addr2 = ProtocolAddress.create('user123', 1);
   * ProtocolAddress.equals(addr1, addr2); // true
   * ```
   */
  export function equals(a: ProtocolAddress, b: ProtocolAddress): boolean {
    return a.userId === b.userId && a.deviceId === b.deviceId;
  }

  /**
   * Check if address belongs to a specific user (ignoring device).
   *
   * @param address - Address to check
   * @param userId - User ID to match
   * @returns true if address belongs to userId
   *
   * @example
   * ```typescript
   * const address = ProtocolAddress.create('user123', 1);
   * ProtocolAddress.isUser(address, 'user123'); // true
   * ProtocolAddress.isUser(address, 'user456'); // false
   * ```
   */
  export function isUser(address: ProtocolAddress, userId: string): boolean {
    return address.userId === userId;
  }

  /**
   * Validate that a string is a valid address format.
   *
   * Optimized to avoid exception overhead by using internal tryParse().
   *
   * @param address - String to validate
   * @returns true if valid address format
   *
   * @example
   * ```typescript
   * ProtocolAddress.isValid('user123:1'); // true
   * ProtocolAddress.isValid('invalid');   // false
   * ```
   */
  export function isValid(address: string): boolean {
    return tryParse(address).error === null;
  }

  /**
   * Create a storage key for looking up SessionRecords by ProtocolAddress.
   *
   * Sessions are looked up by ProtocolAddress, while individual states within
   * a SessionRecord are identified by `baseKey`.
   *
   * Format: `session:${userId}:${deviceId}`
   *
   * @param address - Remote party's protocol address
   * @returns Storage key for SessionRecord lookup
   *
   * @example
   * ```typescript
   * const remoteAddr = ProtocolAddress.create('bob', 2);
   * const storageKey = ProtocolAddress.toStorageKey(remoteAddr);
   * // Returns: "session:bob:2"
   * ```
   */
  export function toStorageKey(address: ProtocolAddress): string {
    return `session:${address.userId}:${address.deviceId}`;
  }

  /**
   * Parse a storage key back into a ProtocolAddress.
   *
   * @param storageKey - Storage key in "session:userId:deviceId" format
   * @returns Parsed ProtocolAddress
   * @throws {Error} If storage key format is invalid
   *
   * @example
   * ```typescript
   * const address = ProtocolAddress.fromStorageKey('session:bob:2');
   * // Returns: { userId: 'bob', deviceId: 2 }
   * ```
   */
  export function fromStorageKey(storageKey: string): ProtocolAddress {
    const parts = storageKey.split(':');
    if (parts.length !== 3 || parts[0] !== 'session') {
      throw new Error(
        `Invalid storage key format: "${storageKey}". Expected "session:userId:deviceId"`
      );
    }

    const userId = parts[1];
    const deviceId = parseInt(parts[2] ?? '', 10);

    if (isNaN(deviceId)) {
      throw new Error(`Invalid deviceId in storage key: "${parts[2]}"`);
    }

    // Use shared validation
    const error = validateComponents(userId, deviceId);
    if (error) {
      throw new Error(`Invalid storage key: ${error}`);
    }

    return { userId: userId!, deviceId };
  }
}
