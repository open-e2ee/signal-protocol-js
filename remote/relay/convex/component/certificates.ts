import { ed25519 } from '@noble/curves/ed25519.js';
import { v } from 'convex/values';
import type { PrivateKey, PublicKey } from '../../../../keys/branded';
import { decodeCompositeIdentityV1 } from '../../../../keys/identity';
import {
  bytesToBase64,
  base64ToBytes,
} from '../../../../internal/crypto/utils';
import {
  encodeSenderCertificate,
  encodeSenderCertificateData,
  encodeServerCertificate,
  encodeServerCertificateData,
} from '../../../../internal/protocol/sealed-sender/proto';
import { CERTIFICATE_EXPIRATION_MS } from '../../../../internal/protocol/sealed-sender/types';
import {
  SEALED_SENDER_ROOT_LABEL,
  SEALED_SENDER_SERVER_LABEL,
  deriveSealedSenderPrivateKey,
} from '../../../../internal/protocol/sealed-sender/trust-root';
import { asBase64 } from '../../../../types/utils';
import { mutation } from './_generated/server';
import { callerIdentityArgs, rememberAccount } from './accounts';
import { relayError } from './errors';
import { groupServerSecretParams } from './runtime';

const REFRESH_MARGIN_MS = 5 * 60 * 1000;

/**
 * The `id` this relay stamps on its server certificate.
 *
 * One signing key, so one identifier; revocation lists are keyed by it.
 */
const SERVER_CERTIFICATE_ID = 1;

async function derivePrivateKey(label: string): Promise<PrivateKey> {
  return bytesToBase64(
    await deriveSealedSenderPrivateKey(
      groupServerSecretParams().signingKeyPair.signingKey,
      label
    )
  ) as PrivateKey;
}

async function certificateAuthority() {
  const rootPrivateKey = await derivePrivateKey(SEALED_SENDER_ROOT_LABEL);
  const serverPrivateKey = await derivePrivateKey(SEALED_SENDER_SERVER_LABEL);
  const rootPublicKey = bytesToBase64(
    ed25519.getPublicKey(base64ToBytes(rootPrivateKey))
  ) as PublicKey;
  const serverPublicKey = bytesToBase64(
    ed25519.getPublicKey(base64ToBytes(serverPrivateKey))
  ) as PublicKey;
  const serverCertificateBytes = encodeServerCertificateData({
    id: SERVER_CERTIFICATE_ID,
    key: base64ToBytes(serverPublicKey),
  });
  const serverSignature = ed25519.sign(
    serverCertificateBytes,
    base64ToBytes(rootPrivateKey)
  );
  const serializedServerCertificate = encodeServerCertificate({
    certificate: serverCertificateBytes,
    signature: serverSignature,
  });
  return {
    rootPublicKey,
    serverPrivateKey,
    serializedServerCertificate,
  };
}

/** The deterministic trust root applications pin for sender certificates. */
export async function senderCertificateTrustRoot(): Promise<PublicKey> {
  return (await certificateAuthority()).rootPublicKey;
}

export const issueSenderCertificate = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.string(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const device = await ctx.db
      .query('devices')
      .withIndex('by_user_id_and_device_id', (q) =>
        q
          .eq('userId', input.callerUserId)
          .eq('deviceId', input.deviceId)
      )
      .unique();
    if (!device?.registered) {
      throw relayError(
        'NOT_FOUND',
        404,
        `Registered device ${input.deviceId} not found`
      );
    }
    const identity = await ctx.db
      .query('identityKeys')
      .withIndex('by_user_id_and_identity_type', (q) =>
        q.eq('userId', input.callerUserId).eq('identityType', 'aci')
      )
      .unique();
    if (!identity) {
      throw relayError(
        'NOT_FOUND',
        404,
        'The account has no ACI identity key'
      );
    }
    const composite = decodeCompositeIdentityV1(
      base64ToBytes(asBase64(identity.compositeIdentity))
    );
    const now = Date.now();
    const existing = await ctx.db
      .query('senderCertificates')
      .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
        q
          .eq('userId', input.callerUserId)
          .eq('deviceId', input.deviceId)
          .eq('identityType', 'aci')
      )
      .unique();
    if (
      existing &&
      existing.identityKey === composite.x25519PublicKey &&
      existing.expiresAt > now + REFRESH_MARGIN_MS
    ) {
      return existing.certificate;
    }
    const authority = await certificateAuthority();
    const expiresAt = now + CERTIFICATE_EXPIRATION_MS;
    const certificateBytes = encodeSenderCertificateData({
      senderDevice: input.deviceId,
      expires: expiresAt,
      identityKey: base64ToBytes(composite.x25519PublicKey),
      signerCertificate: authority.serializedServerCertificate,
      senderUuid: input.callerUserId,
    });
    const signature = ed25519.sign(
      certificateBytes,
      base64ToBytes(authority.serverPrivateKey)
    );
    const encoded = bytesToBase64(
      encodeSenderCertificate({
        certificate: certificateBytes,
        signature,
      })
    );
    const value = {
      userId: input.callerUserId,
      deviceId: input.deviceId,
      identityType: 'aci' as const,
      identityKey: composite.x25519PublicKey,
      certificate: encoded,
      issuedAt: now,
      expiresAt,
    };
    if (existing) {
      await ctx.db.replace(existing._id, value);
    } else {
      await ctx.db.insert('senderCertificates', value);
    }
    return encoded;
  },
});
