/**
 * URL utilities for safety number deep links.
 *
 * Enables safety number QR codes to work with native camera apps (iOS/Android).
 * When scanned outside the app, the URL opens the host application to the
 * verification screen.
 *
 * The universal-link domain and custom scheme are **configurable**. They default
 * to the `open-e2ee.dev` domain. Every function accepts an optional
 * {@link VerifyLinkConfig}, so a consuming application can route links through
 * its own domain and URL scheme.
 *
 * Default URL Format:
 *   https://verify.open-e2ee.dev/safety-number?g={generatorId}&u={otherUserId}&t={type}&c={contextId}&d={data}
 *
 * Default Custom Scheme (also supported):
 *   signalprotocol://verify?g={generatorId}&u={otherUserId}&t={type}&c={contextId}&d={data}
 *
 * @example
 * ```typescript
 * import { generateVerifyUrl, parseVerifyUrl, isVerifyUrl } from './url';
 *
 * // Generate URL for QR code (uses open-e2ee.dev defaults)
 * const url = generateVerifyUrl({
 *   generatorUserId: 'my_user_id_abc123',
 *   otherUserId: 'jx79f527wxe7k89cn9xq4zh4n97yhyp1',
 *   contextType: 'dm',
 *   contextId: 'abc123',
 *   qrData: 'CAISIgoguD3F...',
 * });
 *
 * // Route links through a custom domain/scheme
 * const config = { baseUrl: 'https://verify.example.com/sn', schemeUrl: 'example://verify' };
 * const branded = generateVerifyUrl(params, config);
 *
 * // Parse URL from scanned QR
 * const parsed = parseVerifyUrl(url);
 * if (parsed) {
 *   // Navigate to safety number screen with params
 * }
 * ```
 */

// URL-safe base64 encoding utilities (RFC 4648 §5)
import { base64ToUrlSafe, urlSafeToBase64 } from '../internal/crypto';

// ============================================================================
// Configuration
// ============================================================================

/**
 * Configuration for safety-number verification deep links.
 *
 * Both fields are mandatory, so a config always carries every value. Use
 * {@link DEFAULT_VERIFY_LINK_CONFIG} as a base when overriding a single field.
 */
export interface VerifyLinkConfig {
  /** Universal-link base, including path (e.g. `https://verify.example.com/safety-number`). */
  baseUrl: string;
  /** Custom URL scheme prefix (e.g. `example://verify`). */
  schemeUrl: string;
}

/**
 * Default verification link configuration, targeting the `open-e2ee.dev`
 * domain. Override per call via the `config` parameter on each function.
 */
export const DEFAULT_VERIFY_LINK_CONFIG: VerifyLinkConfig = {
  baseUrl: 'https://verify.open-e2ee.dev/safety-number',
  schemeUrl: 'signalprotocol://verify',
};

/** Default universal-link base. Prefer {@link DEFAULT_VERIFY_LINK_CONFIG}. */
export const VERIFY_BASE_URL = DEFAULT_VERIFY_LINK_CONFIG.baseUrl;

/** Default custom URL scheme. Prefer {@link DEFAULT_VERIFY_LINK_CONFIG}. */
export const VERIFY_SCHEME_URL = DEFAULT_VERIFY_LINK_CONFIG.schemeUrl;

// ============================================================================
// Types
// ============================================================================

/**
 * Parameters encoded in a verification URL.
 */
export interface VerifyUrlParams {
  /** The user who generated the QR code (self from generator's perspective) */
  generatorUserId: string;
  /** Other user's Convex ID (from generator's perspective) */
  otherUserId: string;
  /** Context type: direct message or dynamic group */
  contextType: 'dm' | 'dynamic';
  /** Context ID (conversation or dynamic ID) */
  contextId: string;
  /** Base64-encoded protobuf fingerprint data */
  qrData: string;
}

// ============================================================================
// URL Generation
// ============================================================================

function encodeParams(params: VerifyUrlParams): string {
  return new URLSearchParams({
    g: params.generatorUserId, // Who generated this QR code
    u: params.otherUserId, // The "other user" from generator's perspective
    t: params.contextType,
    c: params.contextId,
    d: base64ToUrlSafe(params.qrData), // Use base64url to avoid +/= corruption in URLs
  }).toString();
}

/**
 * Generate a verification deep link URL for QR code display.
 *
 * The URL contains all information needed to:
 * 1. Open the app (via universal link or custom scheme)
 * 2. Navigate to the correct safety number verification screen
 * 3. Display the fingerprint for manual comparison
 *
 * @param params - Verification parameters to encode
 * @param config - Link configuration (defaults to {@link DEFAULT_VERIFY_LINK_CONFIG})
 * @returns Full URL string for QR code
 *
 * @example
 * ```typescript
 * const url = generateVerifyUrl({
 *   generatorUserId: 'my_user_id_xyz789',
 *   otherUserId: 'jx79f527wxe7k89cn9xq4zh4n97yhyp1',
 *   contextType: 'dm',
 *   contextId: 'kh72g638yxf8l90do0yr5zi5o08ziyr2',
 *   qrData: 'CAISIgoguD3Fkj...',
 * });
 * // Returns: https://verify.open-e2ee.dev/safety-number?g=my_user_id_xyz789&u=jx79f527...&t=dm&c=...&d=...
 * ```
 */
export function generateVerifyUrl(
  params: VerifyUrlParams,
  config: VerifyLinkConfig = DEFAULT_VERIFY_LINK_CONFIG
): string {
  return `${config.baseUrl}?${encodeParams(params)}`;
}

/**
 * Generate a verification URL using the custom scheme.
 * Useful for local development or when universal links are not configured.
 *
 * @param params - Verification parameters to encode
 * @param config - Link configuration (defaults to {@link DEFAULT_VERIFY_LINK_CONFIG})
 * @returns Custom scheme URL string
 */
export function generateVerifySchemeUrl(
  params: VerifyUrlParams,
  config: VerifyLinkConfig = DEFAULT_VERIFY_LINK_CONFIG
): string {
  return `${config.schemeUrl}?${encodeParams(params)}`;
}

// ============================================================================
// URL Parsing
// ============================================================================

/**
 * Check if a string is a verification deep link URL.
 *
 * Matches either the configured universal-link base or the custom scheme.
 *
 * @param data - String to check (typically from QR scanner)
 * @param config - Link configuration (defaults to {@link DEFAULT_VERIFY_LINK_CONFIG})
 * @returns true if string is a verification URL
 *
 * @example
 * ```typescript
 * isVerifyUrl('https://verify.open-e2ee.dev/safety-number?u=abc'); // true
 * isVerifyUrl('signalprotocol://verify?u=abc');                          // true
 * isVerifyUrl('CAISIgoguD3F...');                                        // false (raw protobuf)
 * ```
 */
/**
 * Structural match of a candidate URL against one configured target (the
 * universal-link base or the custom scheme). Requires protocol, host, and
 * pathname to match exactly and rejects embedded credentials and fragments. So
 * lookalikes like `…/safety-number.evil` or `signalprotocol://verify-evil` are
 * NOT accepted (a plain prefix check would accept both).
 */
function matchesTarget(candidate: URL, target: string): boolean {
  let expected: URL;
  try {
    expected = new URL(target);
  } catch {
    return false;
  }
  if (candidate.protocol !== expected.protocol) return false;
  if (candidate.host !== expected.host) return false;
  // Custom schemes yield an empty pathname. Normalize "" and "/".
  if ((candidate.pathname || '/') !== (expected.pathname || '/')) return false;
  if (candidate.username !== '' || candidate.password !== '') return false;
  if (candidate.hash !== '') return false;
  return true;
}

/** Parse a candidate string into a URL only if it matches a configured target. */
function asVerifyTarget(data: string, config: VerifyLinkConfig): URL | null {
  let candidate: URL;
  try {
    candidate = new URL(data);
  } catch {
    return null;
  }
  return matchesTarget(candidate, config.baseUrl) || matchesTarget(candidate, config.schemeUrl)
    ? candidate
    : null;
}

export function isVerifyUrl(
  data: string,
  config: VerifyLinkConfig = DEFAULT_VERIFY_LINK_CONFIG
): boolean {
  return asVerifyTarget(data, config) !== null;
}

/**
 * Parse a verification URL and extract parameters.
 *
 * @param url - Verification URL to parse
 * @param config - Link configuration (defaults to {@link DEFAULT_VERIFY_LINK_CONFIG})
 * @returns Parsed parameters, or null if URL is invalid
 */
export function parseVerifyUrl(
  url: string,
  config: VerifyLinkConfig = DEFAULT_VERIFY_LINK_CONFIG
): VerifyUrlParams | null {
  const target = asVerifyTarget(url, config);
  if (!target) {
    return null;
  }

  try {
    const params = target.searchParams;

    // Reject duplicate required params (ambiguous / potentially hostile).
    for (const key of ['g', 'u', 't', 'c', 'd']) {
      if (params.getAll(key).length > 1) {
        return null;
      }
    }

    const generatorUserId = params.get('g');
    const otherUserId = params.get('u');
    const contextType = params.get('t');
    const contextId = params.get('c');
    const qrData = params.get('d');

    // Validate required params (g is required for new URLs)
    if (!generatorUserId || !otherUserId || !contextType || !contextId || !qrData) {
      return null;
    }

    // Validate context type
    if (contextType !== 'dm' && contextType !== 'dynamic') {
      return null;
    }

    return {
      generatorUserId,
      otherUserId,
      contextType,
      contextId,
      qrData: urlSafeToBase64(qrData), // Convert base64url back to standard base64
    };
  } catch {
    return null;
  }
}

/**
 * Extract QR data from a scanned string.
 *
 * Handles both URL format and legacy raw base64 format.
 * This is a convenience function for the QR scanner.
 *
 * @param scannedData - Raw data from QR scanner
 * @param config - Link configuration (defaults to {@link DEFAULT_VERIFY_LINK_CONFIG})
 * @returns Base64 protobuf data, or null if invalid
 */
export function extractQrData(
  scannedData: string,
  config: VerifyLinkConfig = DEFAULT_VERIFY_LINK_CONFIG
): string | null {
  // Try URL format first
  if (isVerifyUrl(scannedData, config)) {
    const params = parseVerifyUrl(scannedData, config);
    return params?.qrData ?? null;
  }

  // Check for base64url format (from deep link d= parameter)
  // base64url uses - and _ instead of + and /
  if (/^[A-Za-z0-9\-_]+$/.test(scannedData) && scannedData.length >= 10) {
    return urlSafeToBase64(scannedData);
  }

  // Check for standard base64 format (legacy raw QR codes)
  if (/^[A-Za-z0-9+/=]+$/.test(scannedData) && scannedData.length >= 10) {
    return scannedData;
  }

  return null;
}
