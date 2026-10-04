/**
 * Certificate Handling for Sealed Sender
 *
 * Sender and server certificates use protobuf-based signing data.
 * Clients serialize, deserialize, and validate these certificates.
 *
 * Trust chain:
 *   trust_root signs → ServerCertificate.certificateBytes
 *     ServerCertificate.publicKey signs → SenderCertificate.certificateBytes
 *
 * Security: All validation errors use generic messages to prevent fingerprinting.
 *
 */

import type {
  SenderCertificate,
  SenderCertificateValidationPolicy,
  ServerCertificate,
} from './types';
import { REVOKED_CERTIFICATE_IDS } from './types';
import type { Base64 } from '../../../types';
import type { PublicKey, Signature } from '../../../keys';

import { verify, bytesToBase64, base64ToBytes, constantTimeEqual } from '../../crypto';

import { decodeServerCertificateData, decodeServerCertificate, decodeSenderCertificateData, encodeSenderCertificate, decodeSenderCertificate } from './proto';


/** Generic error message for all certificate validation failures */
export {};
const GENERIC_ERROR = 'Sealed sender verification failed';

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize a sender certificate to wire format (outer protobuf wrapper).
 *
 * Output: protobuf-encoded {certificate: certificateBytes, signature: signature}
 *
 * @param cert Certificate to serialize
 * @returns Serialized protobuf bytes
 */
export function serializeSenderCertificate(cert: SenderCertificate): Uint8Array {
  return encodeSenderCertificate({
    certificate: base64ToBytes(cert.certificateBytes),
    signature: base64ToBytes(cert.signature),
  });
}

/**
 * Deserialize a sender certificate from wire format.
 *
 * Decoding layers:
 * 1. Decode outer protobuf → {certificate, signature}
 * 2. Decode inner Certificate protobuf → fields + signer bytes
 * 3. Decode signer bytes as outer ServerCertificate protobuf
 * 4. Decode server cert inner protobuf → {id, key}
 *
 * @param bytes Serialized certificate bytes
 * @returns Deserialized certificate
 * @throws Error (generic) if data is malformed
 */
export function deserializeSenderCertificate(bytes: Uint8Array): SenderCertificate {
  try {
    // Step 1: Decode outer protobuf → {certificate, signature}
    const outer = decodeSenderCertificate(bytes);

    // Protobuf defaults missing bytes fields to zero-length arrays, so validate
    // required wrapper fields explicitly.
    if (!outer.certificate.length || !outer.signature.length) {
      throw new Error('missing required fields');
    }

    // Step 2: Decode inner Certificate protobuf → parsed fields + signer bytes
    const inner = decodeSenderCertificateData(outer.certificate);

    // Validate inner Certificate has required fields
    if (
      !inner.senderUuid ||
      !inner.identityKey.length ||
      !inner.signerCertificate.length ||
      inner.relayScopeId.length !== 16
    ) {
      throw new Error('missing required fields');
    }

    // Step 3: Decode signer bytes as outer ServerCertificate protobuf
    const signerOuter = decodeServerCertificate(inner.signerCertificate);

    // Validate signer has required fields
    if (!signerOuter.certificate.length || !signerOuter.signature.length) {
      throw new Error('missing required fields');
    }

    // Step 4: Decode server cert inner protobuf → {id, key}
    const signerInner = decodeServerCertificateData(signerOuter.certificate);

    // Validate server cert inner data
    if (
      !signerInner.key.length ||
      !Number.isSafeInteger(signerInner.notBefore) ||
      !Number.isSafeInteger(signerInner.notAfter) ||
      signerInner.notBefore <= 0 ||
      signerInner.notAfter < signerInner.notBefore
    ) {
      throw new Error('missing required fields');
    }

    // Build the full ServerCertificate
    const signer: ServerCertificate = {
      id: signerInner.id,
      publicKey: bytesToBase64(signerInner.key),
      notBefore: signerInner.notBefore,
      notAfter: signerInner.notAfter,
      certificateBytes: bytesToBase64(signerOuter.certificate),
      signature: bytesToBase64(signerOuter.signature),
    };

    return {
      senderUuid: inner.senderUuid,
      senderDeviceId: inner.senderDevice,
      senderIdentityKey: bytesToBase64(inner.identityKey),
      expires: inner.expires,
      senderE164: inner.senderE164,
      relayScopeId: bytesToBase64(inner.relayScopeId),
      signer,
      certificateBytes: bytesToBase64(outer.certificate),
      signature: bytesToBase64(outer.signature),
    };
  } catch {
    throw new Error(GENERIC_ERROR);
  }
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate a sender certificate against trust roots.
 *
 * Validation order:
 * 1. Check revocation of embedded server cert ID
 * 2. Validate server cert signature against trust roots (constant-time OR)
 * 3. Verify sender cert signature using server cert's public key
 * 4. Check expiration
 *
 * @param cert Certificate to validate
 * @param trustRoots Ed25519 trust root public keys
 * @param currentTime Optional timestamp for expiration check (defaults to Date.now())
 * @param policy Required deployment scope and issuer revocation policy
 * @throws Error (generic) if validation fails
 */
export async function validateSenderCertificate(
  cert: SenderCertificate,
  trustRoots: Base64[],
  currentTime: number | undefined,
  policy: SenderCertificateValidationPolicy
): Promise<void> {
  const now = currentTime ?? Date.now();

  // Must have at least one trust root
  if (trustRoots.length === 0) {
    throw new Error(GENERIC_ERROR);
  }
  if (base64ToBytes(policy.expectedRelayScopeId).length !== 16) {
    throw new Error(GENERIC_ERROR);
  }

  // Step 1: Check revocation by server certificate ID (cheapest check)
  if (
    REVOKED_CERTIFICATE_IDS.includes(cert.signer.id) ||
    policy.revokedIssuerKeyIds?.includes(cert.signer.id)
  ) {
    throw new Error(GENERIC_ERROR);
  }

  if (
    base64ToBytes(cert.relayScopeId).length !== 16 ||
    !constantTimeEqual(
      base64ToBytes(cert.relayScopeId),
      base64ToBytes(policy.expectedRelayScopeId)
    )
  ) {
    throw new Error(GENERIC_ERROR);
  }

  if (
    !Number.isSafeInteger(cert.expires) ||
    cert.expires <= 0 ||
    cert.signer.notBefore > cert.signer.notAfter ||
    !Number.isSafeInteger(cert.signer.notBefore) ||
    !Number.isSafeInteger(cert.signer.notAfter) ||
    cert.signer.notBefore <= 0 ||
    now < cert.signer.notBefore ||
    now > cert.signer.notAfter ||
    cert.expires > cert.signer.notAfter
  ) {
    throw new Error(GENERIC_ERROR);
  }

  // Check every trust root so the control flow does not reveal which root
  // validated the certificate.
  let anyValid = false;
  for (const root of trustRoots) {
    try {
      const ok = await verify(
        root as PublicKey,
        base64ToBytes(cert.signer.certificateBytes),
        cert.signer.signature as Signature
      );
      anyValid = anyValid || ok;
    } catch {
      // Verify failed for this root, continue checking others
    }
  }
  if (!anyValid) {
    throw new Error(GENERIC_ERROR);
  }

  // Step 3: Verify sender cert signature using signer's public key
  try {
    const isValid = await verify(
      cert.signer.publicKey as PublicKey,
      base64ToBytes(cert.certificateBytes),
      cert.signature as Signature
    );
    if (!isValid) {
      throw new Error(GENERIC_ERROR);
    }
  } catch {
    throw new Error(GENERIC_ERROR);
  }

  // Step 4: Check expiration
  // A certificate remains valid at its exact expiration timestamp.
  if (now > cert.expires) {
    throw new Error(GENERIC_ERROR);
  }
}

/**
 * Validate a server certificate against trust roots.
 *
 * Checks:
 * 1. Certificate ID not in revocation list
 * 2. Signature over certificateBytes verified by at least one trust root
 *
 * @param cert Server certificate to validate
 * @param trustRoots Ed25519 trust root public keys
 * @param currentTime Optional timestamp for issuer validity (defaults to Date.now())
 * @throws Error (generic) if validation fails
 */
export async function validateServerCertificate(
  cert: ServerCertificate,
  trustRoots: Base64[],
  currentTime = Date.now()
): Promise<void> {
  // Check revocation
  if (REVOKED_CERTIFICATE_IDS.includes(cert.id)) {
    throw new Error(GENERIC_ERROR);
  }

  if (
    !Number.isSafeInteger(cert.notBefore) ||
    !Number.isSafeInteger(cert.notAfter) ||
    cert.notBefore <= 0 ||
    cert.notAfter < cert.notBefore ||
    currentTime < cert.notBefore ||
    currentTime > cert.notAfter
  ) {
    throw new Error(GENERIC_ERROR);
  }

  // Validate public key length
  const publicKeyBytes = base64ToBytes(cert.publicKey);
  if (publicKeyBytes.length !== 32) {
    throw new Error(GENERIC_ERROR);
  }

  // Constant-time trust root validation
  let anyValid = false;
  for (const root of trustRoots) {
    try {
      const ok = await verify(
        root as PublicKey,
        base64ToBytes(cert.certificateBytes),
        cert.signature as Signature
      );
      anyValid = anyValid || ok;
    } catch {
      // Continue checking other roots
    }
  }
  if (!anyValid) {
    throw new Error(GENERIC_ERROR);
  }
}
