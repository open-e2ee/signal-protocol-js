import {
  base64ToBytes,
  bytesToBase64,
  constantTimeEqual,
  verify,
} from '../crypto';
import type { Base64 } from '../../types';
import type { PublicKey, Signature } from '../../keys';
import { validateServerCertificate } from '../protocol/sealed-sender/certificate';
import {
  decodeServerCertificate,
  decodeServerCertificateData,
} from '../protocol/sealed-sender/proto';
import { decodeGroupTrustRoot } from './trust-root';

const DOMAIN = 'OpenE2EE Relay group authority v1';
const MAXIMUM_CERTIFICATE_BYTES = 4096;

export interface GroupAuthorityFields {
  readonly relayScopeId: Uint8Array;
  readonly keyId: string;
  readonly notBeforeMilliseconds: number;
  readonly notAfterMilliseconds: number;
  readonly trustRoot: Uint8Array;
}

export interface SignedGroupAuthority {
  readonly certificate: string;
  readonly signature: string;
  readonly signerCertificate: string;
}

function fail(): never {
  throw new Error('Group authority verification failed');
}

function bytes(value: unknown, maximum: number): Uint8Array {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(maximum / 3))
    fail();
  const decoded = base64ToBytes(value as Base64);
  if (decoded.length > maximum || bytesToBase64(decoded) !== value) fail();
  return decoded;
}

/** Canonical domain-separated public authority fields. No private material is accepted. */
export function encodeGroupAuthority(fields: GroupAuthorityFields): Uint8Array {
  if (
    fields.relayScopeId.length !== 16 ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(fields.keyId) ||
    !Number.isSafeInteger(fields.notBeforeMilliseconds) ||
    !Number.isSafeInteger(fields.notAfterMilliseconds) ||
    fields.notBeforeMilliseconds <= 0 ||
    fields.notAfterMilliseconds <= fields.notBeforeMilliseconds ||
    !decodeGroupTrustRoot(fields.trustRoot).serverSigningPublicKey
  )
    fail();
  return new TextEncoder().encode(
    JSON.stringify([
      DOMAIN,
      bytesToBase64(fields.relayScopeId),
      fields.keyId,
      fields.notBeforeMilliseconds,
      fields.notAfterMilliseconds,
      bytesToBase64(fields.trustRoot),
    ])
  );
}

/** Verify project keys under the caller's pinned environment root, never a downloaded root. */
export async function verifyGroupAuthority(
  value: unknown,
  policy: {
    readonly relayScopeId: Uint8Array;
    readonly trustRoots: readonly Uint8Array[];
    readonly revokedIssuerKeyIds: readonly number[];
    readonly nowMilliseconds: number;
  }
): Promise<GroupAuthorityFields> {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      Object.keys(value).sort().join(',') !==
        'certificate,signature,signerCertificate' ||
      !('certificate' in value) ||
      !('signature' in value) ||
      !('signerCertificate' in value) ||
      !Number.isSafeInteger(policy.nowMilliseconds) ||
      policy.nowMilliseconds <= 0
    )
      fail();
    const certificate = bytes(value.certificate, MAXIMUM_CERTIFICATE_BYTES);
    const signature = bytes(value.signature, 64);
    const signerBytes = bytes(value.signerCertificate, 2048);
    if (signature.length !== 64) fail();
    const decoded: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(certificate)
    );
    if (
      !Array.isArray(decoded) ||
      decoded.length !== 6 ||
      decoded[0] !== DOMAIN ||
      typeof decoded[2] !== 'string' ||
      typeof decoded[3] !== 'number' ||
      typeof decoded[4] !== 'number'
    )
      fail();
    const fields = {
      relayScopeId: bytes(decoded[1], 16),
      keyId: decoded[2],
      notBeforeMilliseconds: decoded[3],
      notAfterMilliseconds: decoded[4],
      trustRoot: bytes(decoded[5], 1024),
    };
    if (
      !constantTimeEqual(certificate, encodeGroupAuthority(fields)) ||
      !constantTimeEqual(fields.relayScopeId, policy.relayScopeId) ||
      policy.nowMilliseconds < fields.notBeforeMilliseconds ||
      policy.nowMilliseconds >= fields.notAfterMilliseconds
    )
      fail();
    const outer = decodeServerCertificate(signerBytes);
    const issuer = decodeServerCertificateData(outer.certificate);
    if (
      policy.revokedIssuerKeyIds.includes(issuer.id) ||
      fields.notBeforeMilliseconds < issuer.notBefore ||
      fields.notAfterMilliseconds > issuer.notAfter ||
      outer.signature.length !== 64
    )
      fail();
    await validateServerCertificate(
      {
        id: issuer.id,
        publicKey: bytesToBase64(issuer.key),
        notBefore: issuer.notBefore,
        notAfter: issuer.notAfter,
        certificateBytes: bytesToBase64(outer.certificate),
        signature: bytesToBase64(outer.signature),
      },
      policy.trustRoots.map(bytesToBase64),
      policy.nowMilliseconds
    );
    if (
      !(await verify(
        bytesToBase64(issuer.key) as PublicKey,
        certificate,
        bytesToBase64(signature) as Signature
      ))
    )
      fail();
    return fields;
  } catch {
    return fail();
  }
}
