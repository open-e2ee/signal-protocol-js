/**
 * ML-KEM Braid Custom Error Types
 *
 * Granular errors for programmatic handling and diagnostics.
 *
 * @module ml-kem-braid/errors
 */

// =============================================================================
// Error Codes
// =============================================================================

/**
 * Error codes for programmatic error handling
 */
export {};
export enum ErrorCode {
  // Incremental KEM errors
  KEM_NOT_AVAILABLE = 'KEM_NOT_AVAILABLE',
  INVALID_EK_SEED_SIZE = 'INVALID_EK_SEED_SIZE',
  INVALID_EK_VECTOR_SIZE = 'INVALID_EK_VECTOR_SIZE',
  INVALID_DK_SIZE = 'INVALID_DK_SIZE',
  INVALID_CT1_SIZE = 'INVALID_CT1_SIZE',
  INVALID_CT2_SIZE = 'INVALID_CT2_SIZE',
  INVALID_HEK_SIZE = 'INVALID_HEK_SIZE',
  INVALID_RANDOMNESS_SIZE = 'INVALID_RANDOMNESS_SIZE',
  ENCAPSULATION_FAILED = 'ENCAPSULATION_FAILED',
  DECAPSULATION_FAILED = 'DECAPSULATION_FAILED',

  // Authenticator errors
  MAC_VERIFICATION_FAILED = 'MAC_VERIFICATION_FAILED',
  EK_HASH_BINDING_FAILED = 'EK_HASH_BINDING_FAILED',
  INVALID_MAC_SIZE = 'INVALID_MAC_SIZE',
  AUTHENTICATOR_NOT_INITIALIZED = 'AUTHENTICATOR_NOT_INITIALIZED',
  INVALID_ROOT_KEY_SIZE = 'INVALID_ROOT_KEY_SIZE',
  INVALID_UPDATE_KEY_SIZE = 'INVALID_UPDATE_KEY_SIZE',

  // State machine errors
  INVALID_STATE_TRANSITION = 'INVALID_STATE_TRANSITION',
  INVALID_MESSAGE_TYPE = 'INVALID_MESSAGE_TYPE',
  EPOCH_MISMATCH = 'EPOCH_MISMATCH',
  STATE_MACHINE_NOT_INITIALIZED = 'STATE_MACHINE_NOT_INITIALIZED',

  // Erasure coding errors
  CHUNK_DECODE_FAILED = 'CHUNK_DECODE_FAILED',
  INSUFFICIENT_CHUNKS = 'INSUFFICIENT_CHUNKS',
  INVALID_CHUNK_INDEX = 'INVALID_CHUNK_INDEX',
  INVALID_CHUNK_SIZE = 'INVALID_CHUNK_SIZE',
  ENCODING_FAILED = 'ENCODING_FAILED',

  // KDF errors
  INVALID_SHARED_SECRET_SIZE = 'INVALID_SHARED_SECRET_SIZE',
  KDF_FAILED = 'KDF_FAILED',

  // General errors
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
}

// =============================================================================
// Base Error Class
// =============================================================================

/**
 * Base error class for all ML-KEM Braid errors
 *
 * Provides structured error information with error codes for
 * programmatic error handling.
 */
export class MLKEMBraidError extends Error {
  /**
   * Create a new ML-KEM Braid error
   * @param message - Human-readable error message
   * @param code - Error code for programmatic handling
   * @param context - Optional context information
   */
  constructor(
    message: string,
    public readonly code: ErrorCode,
    public readonly context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'MLKEMBraidError';
    // Maintains proper stack trace in V8 environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MLKEMBraidError);
    }
  }

  /**
   * Create a string representation including code and context
   */
  toString(): string {
    let str = `${this.name} [${this.code}]: ${this.message}`;
    if (this.context) {
      str += ` (${JSON.stringify(this.context)})`;
    }
    return str;
  }
}

// =============================================================================
// Module-Specific Error Classes
// =============================================================================

/**
 * Errors from the Incremental KEM module
 *
 * Thrown when:
 * - Key generation fails
 * - Encapsulation fails (Encaps1, Encaps2)
 * - Decapsulation fails
 * - Input validation fails for KEM operations
 */
export class IncrementalKEMError extends MLKEMBraidError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.KEM_NOT_AVAILABLE,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'IncrementalKEMError';
  }

  /**
   * Factory: Create error for invalid input size
   */
  static invalidSize(paramName: string, actual: number, expected: number): IncrementalKEMError {
    const codeMap: Record<string, ErrorCode> = {
      ek_seed: ErrorCode.INVALID_EK_SEED_SIZE,
      ek_vector: ErrorCode.INVALID_EK_VECTOR_SIZE,
      dk: ErrorCode.INVALID_DK_SIZE,
      ct1: ErrorCode.INVALID_CT1_SIZE,
      ct2: ErrorCode.INVALID_CT2_SIZE,
      hek: ErrorCode.INVALID_HEK_SIZE,
      randomness: ErrorCode.INVALID_RANDOMNESS_SIZE,
    };

    return new IncrementalKEMError(
      `Invalid ${paramName} size: ${actual}, expected ${expected}`,
      codeMap[paramName] || ErrorCode.INVALID_ARGUMENT,
      { paramName, actual, expected }
    );
  }

  /**
   * Factory: Create error for unavailable KEM
   */
  static notAvailable(reason?: string): IncrementalKEMError {
    return new IncrementalKEMError(
      `Incremental ML-KEM not available${reason ? `: ${reason}` : ''}. ` +
        '@noble/post-quantum does not expose incremental API. ' +
        'See README.md for implementation options.',
      ErrorCode.KEM_NOT_AVAILABLE,
      { reason }
    );
  }
}

/**
 * Errors from the Authenticator module
 *
 * Thrown when:
 * - MAC verification fails
 * - Authenticator is not initialized
 * - Invalid key sizes provided
 */
export class AuthenticatorError extends MLKEMBraidError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.MAC_VERIFICATION_FAILED,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'AuthenticatorError';
  }

  /**
   * Factory: Create error for MAC verification failure
   */
  static macVerificationFailed(
    macType: 'header' | 'ciphertext',
    epoch: bigint
  ): AuthenticatorError {
    return new AuthenticatorError(
      `${macType === 'header' ? 'Header' : 'Ciphertext'} MAC verification failed at epoch ${epoch}`,
      ErrorCode.MAC_VERIFICATION_FAILED,
      { macType, epoch: Number(epoch) }
    );
  }

  /**
   * Factory: Create error for EK hash binding verification failure
   *
   * EK (encapsulation key) is authenticated via hash binding:
   * The ML-KEM Braid specification defines
   * hek = SHA3-256(ek_seed || ek_vector), where hek is MAC'd in the header.
   */
  static ekHashBindingFailed(epoch: bigint): AuthenticatorError {
    return new AuthenticatorError(
      `EK hash binding verification failed at epoch ${epoch}: SHA3-256(ek_seed || ek_vector) != hek`,
      ErrorCode.EK_HASH_BINDING_FAILED,
      { macType: 'ek_hash_binding', epoch: Number(epoch) }
    );
  }

  /**
   * Factory: Create error for invalid key size
   */
  static invalidKeySize(
    keyType: 'root_key' | 'update_key' | 'mac',
    actual: number,
    expected: number
  ): AuthenticatorError {
    const codeMap: Record<string, ErrorCode> = {
      root_key: ErrorCode.INVALID_ROOT_KEY_SIZE,
      update_key: ErrorCode.INVALID_UPDATE_KEY_SIZE,
      mac: ErrorCode.INVALID_MAC_SIZE,
    };

    return new AuthenticatorError(
      `Invalid ${keyType} size: ${actual}, expected ${expected}`,
      codeMap[keyType] || ErrorCode.INVALID_ARGUMENT,
      { keyType, actual, expected }
    );
  }
}

/**
 * Errors from the State Machine module
 *
 * Thrown when:
 * - Invalid state transition attempted
 * - Invalid message type received
 * - Epoch mismatch detected
 */
export class StateTransitionError extends MLKEMBraidError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.INVALID_STATE_TRANSITION,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'StateTransitionError';
  }

  /**
   * Factory: Create error for invalid state transition
   */
  static invalidTransition(
    fromState: string,
    event: string,
    role?: 'alice' | 'bob'
  ): StateTransitionError {
    return new StateTransitionError(
      `Invalid transition from ${fromState} on event ${event}${role ? ` (${role})` : ''}`,
      ErrorCode.INVALID_STATE_TRANSITION,
      { fromState, event, role }
    );
  }

  /**
   * Factory: Create error for invalid message type
   */
  static invalidMessageType(state: string, messageType: number): StateTransitionError {
    return new StateTransitionError(
      `Unexpected message type ${messageType} in state ${state}`,
      ErrorCode.INVALID_MESSAGE_TYPE,
      { state, messageType }
    );
  }

  /**
   * Factory: Create error for epoch mismatch
   */
  static epochMismatch(expected: bigint, received: bigint): StateTransitionError {
    return new StateTransitionError(
      `Epoch mismatch: expected ${expected}, received ${received}`,
      ErrorCode.EPOCH_MISMATCH,
      { expected: Number(expected), received: Number(received) }
    );
  }
}

/**
 * Errors from the Erasure Coding module
 *
 * Thrown when:
 * - Chunk decoding fails
 * - Insufficient chunks for reconstruction
 * - Invalid chunk index or size
 */
export class ErasureError extends MLKEMBraidError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.CHUNK_DECODE_FAILED,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'ErasureError';
  }

  /**
   * Factory: Create error for insufficient chunks
   */
  static insufficientChunks(received: number, required: number): ErasureError {
    return new ErasureError(
      `Insufficient chunks for reconstruction: ${received}/${required}`,
      ErrorCode.INSUFFICIENT_CHUNKS,
      { received, required }
    );
  }

  /**
   * Factory: Create error for invalid chunk index
   */
  static invalidChunkIndex(index: number, maxIndex: number): ErasureError {
    return new ErasureError(
      `Invalid chunk index: ${index} (max: ${maxIndex})`,
      ErrorCode.INVALID_CHUNK_INDEX,
      { index, maxIndex }
    );
  }

  /**
   * Factory: Create error for invalid chunk size
   */
  static invalidChunkSize(actual: number, expected: number): ErasureError {
    return new ErasureError(
      `Invalid chunk size: ${actual}, expected ${expected}`,
      ErrorCode.INVALID_CHUNK_SIZE,
      { actual, expected }
    );
  }
}

/**
 * Errors from the KDF module
 *
 * Thrown when:
 * - Invalid key sizes provided
 * - KDF operation fails
 */
export class KDFError extends MLKEMBraidError {
  constructor(
    message: string,
    code: ErrorCode = ErrorCode.KDF_FAILED,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'KDFError';
  }

  /**
   * Factory: Create error for invalid input size
   */
  static invalidSize(paramName: string, actual: number, expected: number): KDFError {
    return new KDFError(
      `Invalid ${paramName} size: ${actual}, expected ${expected}`,
      ErrorCode.INVALID_SHARED_SECRET_SIZE,
      { paramName, actual, expected }
    );
  }
}
