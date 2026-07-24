/**
 * fingerprint.ts
 *
 * Fingerprint/safety number types for identity verification in Signal Protocol.
 * Provides Fingerprint classes for structured TOFU verification.
 *
 * Safety numbers allow users to verify they're communicating with the correct
 * person and detect man-in-the-middle attacks through out-of-band verification
 * (comparing numbers in person, over the phone, via QR code, etc.).
 *
 * @see https://signal.org/docs/specifications/fingerprint/
 */

import type { PublicKey } from '../keys';
import {
  computeFingerprintPair,
  FINGERPRINT_VERSION,
  SCANNABLE_FINGERPRINT_BYTES,
  constantTimeEqual,
} from './core';
import {
  encodeCombinedFingerprints,
  decodeCombinedFingerprints,
  type CombinedFingerprints,
} from './protobuf';
import { bytesToBase64, base64ToBytes } from '../internal/crypto';
import { asBase64 } from '../types';

/**
 * Result of comparing two scannable fingerprints.
 */
export {};
export type CompareResult = 'match' | 'no_match' | 'version_mismatch';

/**
 * Fingerprint for identity verification between two parties.
 *
 * Contains both displayable (numeric) and scannable (QR code) representations
 * of the combined identity fingerprint. Provides Fingerprint class.
 *
 * Deterministic party ordering ensures both participants compute the same
 * fingerprint value.
 *
 * @example
 * ```typescript
 * const fingerprint = new Fingerprint(
 *   myIdentityKey,
 *   theirIdentityKey,
 *   myUserId,
 *   theirUserId
 * );
 *
 * // Show displayable fingerprint in UI
 * const displayable = fingerprint.displayable();
 * console.log(displayable.toString()); // "60-digit number"
 *
 * // Generate QR code for scanning
 * const scannable = fingerprint.scannable();
 * const qrData = scannable.toBuffer();
 * ```
 */
export class Fingerprint {
  private _displayable: DisplayableFingerprint;
  private _scannable: ScannableFingerprint;

  /**
   * Create a new Fingerprint.
   *
   * @param localIdentityKey - Our identity public key
   * @param remoteIdentityKey - Their identity public key
   * @param localIdentifier - Our user ID
   * @param remoteIdentifier - Their user ID
   */
  constructor(
    localIdentityKey: PublicKey,
    remoteIdentityKey: PublicKey,
    localIdentifier: string,
    remoteIdentifier: string
  ) {
    // Compute both parties' single-key fingerprints.
    const pair = computeFingerprintPair(
      localIdentityKey,
      remoteIdentityKey,
      localIdentifier,
      remoteIdentifier
    );

    this._displayable = new DisplayableFingerprint(pair.displayable.replace(/ /g, ''));
    this._scannable = new ScannableFingerprint(
      pair.localFingerprint.scannable,
      pair.remoteFingerprint.scannable,
      FINGERPRINT_VERSION
    );
  }

  /**
   * Get displayable fingerprint for manual verification.
   *
   * Returns a 60-digit numeric string formatted for easy comparison.
   *
   * @returns DisplayableFingerprint instance
   */
  displayable(): DisplayableFingerprint {
    return this._displayable;
  }

  /**
   * Get scannable fingerprint for QR code verification.
   *
   * Returns binary data suitable for QR code encoding.
   *
   * @returns ScannableFingerprint instance
   */
  scannable(): ScannableFingerprint {
    return this._scannable;
  }
}

/**
 * Displayable fingerprint for manual verification.
 *
 * Represents the fingerprint as a 60-digit numeric string formatted
 * in groups of 5 digits for easy reading and comparison.
 *
 * @example
 * ```typescript
 * const displayable = fingerprint.displayable();
 * console.log(displayable.toString());
 * // "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
 * ```
 */
export class DisplayableFingerprint {
  /**
   * Create a DisplayableFingerprint.
   *
   * @param numeric - 60-digit numeric string
   */
  constructor(private numeric: string) {
    if (numeric.length !== 60) {
      throw new Error('Fingerprint must be exactly 60 digits');
    }
    if (!/^\d{60}$/.test(numeric)) {
      throw new Error('Fingerprint must contain only digits');
    }
  }

  /**
   * Get the raw 60-digit string.
   *
   * @returns 60-digit numeric string
   */
  toString(): string {
    return this.numeric;
  }

  /**
   * Get formatted fingerprint with grouping for readability.
   *
   * Formats as groups of 5 digits separated by spaces.
   *
   * @returns Formatted string like "12345 67890 12345 ..."
   */
  formatted(): string {
    return this.numeric.match(/.{1,5}/g)?.join(' ') ?? this.numeric;
  }

  /**
   * Compare this fingerprint with another.
   *
   * @param other - Another DisplayableFingerprint
   * @returns true if fingerprints match
   */
  equals(other: DisplayableFingerprint): boolean {
    const a = new TextEncoder().encode(this.numeric);
    const b = new TextEncoder().encode(other.toString());
    return constantTimeEqual(a, b);
  }

  /**
   * Get individual digit groups for UI display.
   *
   * Returns array of 12 groups of 5 digits each.
   *
   * @returns Array of 12 digit groups
   */
  getGroups(): string[] {
    return this.numeric.match(/.{1,5}/g) ?? [];
  }
}

/**
 * Scannable fingerprint for QR code verification.
 *
 * Contains binary data suitable for encoding in a QR code.
 * Both parties can scan each other's QR codes to verify identity.
 *
 * Uses the versioned fingerprint protobuf format for cross-verification:
 * - When Alice scans Bob's QR, Bob's local fingerprint should equal Alice's remote
 * - When Bob scans Alice's QR, Alice's local fingerprint should equal Bob's remote
 *
 * @example
 * ```typescript
 * const scannable = fingerprint.scannable();
 *
 * // Generate QR code
 * const qrData = scannable.toBuffer();
 * const qrCode = await QRCode.toDataURL(qrData);
 *
 * // Compare scanned codes (implements cross-verification)
 * const result = scannable.compare(scannedBuffer);
 * if (result === 'match') {
 *   // Identity verified!
 * }
 * ```
 */
export class ScannableFingerprint {
  private localFingerprint: Uint8Array;
  private remoteFingerprint: Uint8Array;
  private version: number;

  /**
   * Create a ScannableFingerprint.
   *
   * @param localFingerprint - Local user's 32-byte scannable fingerprint
   * @param remoteFingerprint - Remote user's 32-byte scannable fingerprint
   * @param version - Protocol version (default: 2)
   */
  constructor(
    localFingerprint: Uint8Array,
    remoteFingerprint: Uint8Array,
    version: number = FINGERPRINT_VERSION
  ) {
    if (localFingerprint.length !== SCANNABLE_FINGERPRINT_BYTES) {
      throw new Error(
        `Local fingerprint must be ${SCANNABLE_FINGERPRINT_BYTES} bytes, got ${localFingerprint.length}`
      );
    }
    if (remoteFingerprint.length !== SCANNABLE_FINGERPRINT_BYTES) {
      throw new Error(
        `Remote fingerprint must be ${SCANNABLE_FINGERPRINT_BYTES} bytes, got ${remoteFingerprint.length}`
      );
    }

    this.localFingerprint = localFingerprint;
    this.remoteFingerprint = remoteFingerprint;
    this.version = version;
  }

  /**
   * Get the binary data for QR code encoding.
   *
   * Encodes as protobuf CombinedFingerprints message.
   *
   * @returns Uint8Array suitable for QR code generation
   */
  toBuffer(): Uint8Array {
    return encodeCombinedFingerprints({
      version: this.version,
      localFingerprint: this.localFingerprint,
      remoteFingerprint: this.remoteFingerprint,
    });
  }

  /**
   * Get the data as base64 string.
   *
   * Useful for transmission or storage.
   *
   * @returns Base64-encoded fingerprint data
   */
  toBase64(): string {
    return bytesToBase64(this.toBuffer());
  }

  /**
   * Compare this scannable fingerprint with scanned data.
   *
   * Implements cross-verification swap logic:
   * - Their local fingerprint should equal our remote fingerprint
   * - Their remote fingerprint should equal our local fingerprint
   *
   * Uses best-effort full-scan equality for both fixed-size fingerprints.
   * JavaScript/JIT execution does not provide a hard constant-time guarantee.
   *
   * @param scannedData - Raw bytes from scanned QR code
   * @returns 'match' | 'no_match' | 'version_mismatch'
   *
   *
   * @example
   * ```typescript
   * // After scanning their QR code
   * const scannedBuffer = decodeQRCode(qrImage);
   * const result = myFingerprint.scannable().compare(scannedBuffer);
   *
   * if (result === 'match') {
   *   // Identity verified!
   * } else if (result === 'no_match') {
   *   // SECURITY WARNING! Keys don't match
   * } else if (result === 'version_mismatch') {
   *   // Different protocol versions
   * }
   * ```
   */
  compare(scannedData: Uint8Array): CompareResult {
    let decoded: CombinedFingerprints;
    try {
      decoded = decodeCombinedFingerprints(scannedData);
    } catch {
      return 'no_match';
    }

    // Check version
    if (decoded.version !== this.version) {
      return 'version_mismatch';
    }

    // CRITICAL SWAP: their local = our remote, their remote = our local
    // Compare both fixed-size components before combining the results.
    const localMatch = constantTimeEqual(decoded.localFingerprint, this.remoteFingerprint);
    const remoteMatch = constantTimeEqual(decoded.remoteFingerprint, this.localFingerprint);

    return localMatch && remoteMatch ? 'match' : 'no_match';
  }

  /**
   * Compare this scannable fingerprint with another ScannableFingerprint.
   *
   * Convenience method that extracts the buffer from the other fingerprint.
   *
   * @param other - Another ScannableFingerprint
   * @returns 'match' | 'no_match' | 'version_mismatch'
   */
  compareWith(other: ScannableFingerprint): CompareResult {
    return this.compare(other.toBuffer());
  }

  /**
   * Parse a ScannableFingerprint from base64 string.
   *
   * @param base64 - Base64-encoded fingerprint data
   * @returns ScannableFingerprint instance
   */
  static fromBase64(base64: string): ScannableFingerprint {
    const data = base64ToBytes(asBase64(base64));
    const decoded = decodeCombinedFingerprints(data);
    return new ScannableFingerprint(
      decoded.localFingerprint,
      decoded.remoteFingerprint,
      decoded.version
    );
  }

  /**
   * Parse a ScannableFingerprint from raw bytes.
   *
   * @param data - Protobuf-encoded fingerprint data
   * @returns ScannableFingerprint instance
   */
  static fromBuffer(data: Uint8Array): ScannableFingerprint {
    const decoded = decodeCombinedFingerprints(data);
    return new ScannableFingerprint(
      decoded.localFingerprint,
      decoded.remoteFingerprint,
      decoded.version
    );
  }
}

/**
 * Fingerprint data for compatibility with existing function-based API.
 *
 * This interface matches the existing `SafetyNumber` interface but is
 * extended to support the new class-based API.
 */
export interface FingerprintData {
  /** 60-digit numeric fingerprint */
  numeric: string;

  /** Base64-encoded scannable data for QR codes (protobuf format) */
  scannable: string;

  /** Formatted numeric fingerprint (with spaces) */
  formatted: string;

  /** Fingerprint instance for advanced operations */
  fingerprint: Fingerprint;

  /** ScannableFingerprint instance for verification */
  scannableFingerprint: ScannableFingerprint;
}

/**
 * Create fingerprint data from identity keys and identifiers.
 *
 * This is a convenience function that wraps the Fingerprint class
 * and provides compatibility with the existing function-based API.
 *
 * @param localIdentityKey - Our identity public key
 * @param remoteIdentityKey - Their identity public key
 * @param localIdentifier - Our user ID
 * @param remoteIdentifier - Their user ID
 * @returns FingerprintData with all representations
 *
 * @example
 * ```typescript
 * const data = createFingerprintData(
 *   myKey,
 *   theirKey,
 *   'alice@example.com',
 *   'bob@example.com'
 * );
 *
 * console.log(data.formatted); // Formatted for display
 * const qrCode = generateQRCode(data.scannable); // For scanning
 * ```
 */
export function createFingerprintData(
  localIdentityKey: PublicKey,
  remoteIdentityKey: PublicKey,
  localIdentifier: string,
  remoteIdentifier: string
): FingerprintData {
  const fingerprint = new Fingerprint(
    localIdentityKey,
    remoteIdentityKey,
    localIdentifier,
    remoteIdentifier
  );

  const displayable = fingerprint.displayable();
  const scannable = fingerprint.scannable();

  return {
    numeric: displayable.toString(),
    scannable: scannable.toBase64(),
    formatted: displayable.formatted(),
    fingerprint,
    scannableFingerprint: scannable,
  };
}
