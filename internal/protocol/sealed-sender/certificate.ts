/**
 * Certificate Handling for Sealed Sender
 *
 * Handles creation, serialization, deserialization, and validation of sender
 * and server certificates using protobuf-based signing data.
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
import type { PrivateKey, PublicKey, Signature } from '../../../keys';
import { verify, sign, bytesToBase64, base64ToBytes, constantTimeEqual } from '../../crypto';
import {
  encodeServerCertificateData,
  decodeServerCertificateData,
  encodeServerCertificate,
  decodeServerCertificate,
  encodeSenderCertificateData,
  decodeSenderCertificateData,
  encodeSenderCertificate,
  decodeSenderCertificate,
} from './proto';

/** Generic error message for all certificate validation failures */
export {};
const GENERIC_ERROR = 'Sealed sender verification failed';

// ============================================================================
// Certificate Creation
// ============================================================================

/**
 * Create a server certificate with protobuf-encoded inner Certificate.
 *
 * 1. Protobuf-encode inner Certificate {id, key}
 * 2. Sign with trust root → signature
 * 3. Return full ServerCertificate
 *
 */
export async function createServerCertificate(
  id: number,
  publicKey: Base64,
  trustRootPrivateKey: PrivateKey,
  validity: { notBefore: number; notAfter: number }
): Promise<ServerCertificate> {
  if (
    !Number.isSafeInteger(validity.notBefore) ||
    !Number.isSafeInteger(validity.notAfter) ||
    validity.notBefore <= 0 ||
    validity.notAfter < validity.notBefore
  ) {
    throw new Error(GENERIC_ERROR);
  }

  // Encode inner Certificate protobuf
  const certificateBytesRaw = encodeServerCertificateData({
    id,
    key: base64ToBytes(publicKey),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
  });

  // Sign with trust root
  const signatureBase64 = await sign(trustRootPrivateKey, certificateBytesRaw);

  return {
    id,
    publicKey,
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    certificateBytes: bytesToBase64(certificateBytesRaw),
    signature: signatureBase64,
  };
}

/**
 * Create a sender certificate with protobuf-encoded inner Certificate.
 *
 * 1. Serialize signer → outer ServerCertificate protobuf bytes
 * 2. Build inner Certificate protobuf with all fields + signer bytes
 * 3. Sign certificateBytes with signerPrivateKey → signature
 * 4. Return full SenderCertificate
 *
 */
export async function createSenderCertificate(
  fields: {
    senderUuid: string;
    senderDeviceId: number;
    senderIdentityKey: Base64;
    expires: number;
    senderE164?: string;
    relayScopeId: Base64;
  },
  signer: ServerCertificate,
  signerPrivateKey: PrivateKey
): Promise<SenderCertificate> {
  if (
    base64ToBytes(fields.relayScopeId).length !== 16 ||
    !Number.isSafeInteger(fields.expires) ||
    fields.expires <= 0 ||
    fields.expires > signer.notAfter
  ) {
    throw new Error(GENERIC_ERROR);
  }

  // Serialize the signer as outer ServerCertificate protobuf
  const signerBytes = encodeServerCertificate({
    certificate: base64ToBytes(signer.certificateBytes),
    signature: base64ToBytes(signer.signature),
  });

  // Encode inner Certificate protobuf with correct field numbers
  const certificateBytesRaw = encodeSenderCertificateData({
    senderUuid: fields.senderUuid,
    senderDevice: fields.senderDeviceId,
    senderE164: fields.senderE164,
    expires: fields.expires,
    identityKey: base64ToBytes(fields.senderIdentityKey),
    signerCertificate: signerBytes,
    relayScopeId: base64ToBytes(fields.relayScopeId),
  });

  // Sign with signer's private key
  const signatureBase64 = await sign(signerPrivateKey, certificateBytesRaw);

  return {
    senderUuid: fields.senderUuid,
    senderDeviceId: fields.senderDeviceId,
    senderIdentityKey: fields.senderIdentityKey,
    expires: fields.expires,
    senderE164: fields.senderE164,
    relayScopeId: fields.relayScopeId,
    signer,
    certificateBytes: bytesToBase64(certificateBytesRaw),
    signature: signatureBase64,
  };
}

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
