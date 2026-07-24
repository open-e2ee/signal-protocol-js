import type { CompositeIdentityV1 } from '../../keys';
import { deriveIdentityCommitment } from '../../keys/identity';
import { concatBytes, constantTimeEqual, hmac } from '../crypto';

const MAC_LENGTH = 8;
const MESSAGE_MAC_V1_DOMAIN = new TextEncoder().encode(
  'signal-protocol-js composite identity message mac v1'
);

/** Independent-profile message MAC bound to both canonical identity tuples. */
export function computeCompositeIdentityMessageMac(
  macKey: Uint8Array,
  senderIdentity: CompositeIdentityV1,
  receiverIdentity: CompositeIdentityV1,
  serializedMessage: Uint8Array
): Uint8Array {
  if (macKey.length !== 32) throw new Error(`MAC key must be 32 bytes, got ${macKey.length}`);
  const input = concatBytes(
    MESSAGE_MAC_V1_DOMAIN,
    deriveIdentityCommitment(senderIdentity),
    deriveIdentityCommitment(receiverIdentity),
    serializedMessage
  );
  return hmac(macKey, input).slice(0, MAC_LENGTH);
}

export function verifyCompositeIdentityMessageMac(
  macKey: Uint8Array,
  senderIdentity: CompositeIdentityV1,
  receiverIdentity: CompositeIdentityV1,
  serializedMessage: Uint8Array,
  receivedMac: Uint8Array
): boolean {
  return constantTimeEqual(
    computeCompositeIdentityMessageMac(
      macKey,
      senderIdentity,
      receiverIdentity,
      serializedMessage
    ),
    receivedMac
  );
}
