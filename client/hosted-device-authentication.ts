/** The device authentication key of a hosted store: made once, then kept and read strictly. */
import type { PrivateKey } from '../keys';
import {
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  generateSigningKeyPair,
  sha256,
  sign,
  stringToBytes,
} from '../internal/crypto';
import type { Base64, SignalProtocolLocalStore } from '../types';
import type { HostedSignalProtocolRelayDeviceAuthentication } from './hosted';
import { HostedSignalProtocolRelayResumeError } from './hosted-resume-error';
import {
  hostedStoreRecordKey,
  readHostedStoreRecord,
  writeHostedStoreRecord,
  type HostedStoreRecordKey,
  type HostedStoreRecordPrefix,
} from './hosted-store-records';
import { SIGNAL_RELAY_PROOF_LABELS } from './signal-relay-protocol';

const DEVICE_AUTHENTICATION_METADATA_PREFIX: HostedStoreRecordPrefix = {
  current: 'signalRelay.deviceAuthentication.v2:',
  earlier: 'hostedRelay.deviceAuthentication.v1:',
};

interface StoredDeviceAuthentication {
  publicKey: Base64;
  privateKey: PrivateKey;
}

function decodeStoredDeviceAuthentication(
  value: string,
): StoredDeviceAuthentication {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Stored Signal Protocol Relay device authentication key is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !('publicKey' in parsed) ||
    !('privateKey' in parsed) ||
    typeof parsed.publicKey !== 'string' ||
    typeof parsed.privateKey !== 'string' ||
    base64ToBytes(parsed.publicKey as Base64).length !== 32 ||
    base64ToBytes(parsed.privateKey as Base64).length !== 32
  ) {
    throw new Error('Stored Signal Protocol Relay device authentication key is invalid');
  }
  return parsed as StoredDeviceAuthentication;
}

/** @internal The device authentication key of this store, made once and then kept. */
export async function getOrCreateDeviceAuthentication(
  storage: SignalProtocolLocalStore,
  publishableKey: string,
): Promise<HostedSignalProtocolRelayDeviceAuthentication> {
  const metadataKey = await deviceAuthenticationMetadataKey(publishableKey);
  const stored = await readHostedStoreRecord(storage, metadataKey);
  let keyPair: StoredDeviceAuthentication;
  if (stored) {
    keyPair = decodeStoredDeviceAuthentication(stored);
  } else {
    keyPair = await generateSigningKeyPair();
    await writeHostedStoreRecord(storage, metadataKey, JSON.stringify(keyPair));
  }
  return deviceAuthenticationSigner(keyPair, publishableKey);
}

/** @internal Existing authority reader shared with strict hosted resume. */
export async function getExistingDeviceAuthentication(
  storage: SignalProtocolLocalStore,
  publishableKey: string,
  strict = false,
): Promise<HostedSignalProtocolRelayDeviceAuthentication> {
  let stored: string | null;
  try {
    stored = await readHostedStoreRecord(storage, await deviceAuthenticationMetadataKey(publishableKey));
  } catch (cause) {
    if (strict) {
      throw new HostedSignalProtocolRelayResumeError(
        'RETAINED_STATE_UNREADABLE', 'reading-local-state', { cause }
      );
    }
    throw cause;
  }
  if (!stored) {
    if (strict) {
      throw new HostedSignalProtocolRelayResumeError('RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE', 'reading-local-state');
    }
    throw new Error('Signal Protocol Relay active device authentication key is not registered');
  }
  try {
    return deviceAuthenticationSigner(decodeStoredDeviceAuthentication(stored), publishableKey);
  } catch (cause) {
    if (strict) {
      throw new HostedSignalProtocolRelayResumeError(
        'RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE', 'reading-local-state', { cause }
      );
    }
    throw cause;
  }
}

/** @internal The store record key of the device authentication key of one publishable key. */
export async function deviceAuthenticationMetadataKey(
  publishableKey: string,
): Promise<HostedStoreRecordKey> {
  return hostedStoreRecordKey(
    DEVICE_AUTHENTICATION_METADATA_PREFIX,
    bytesToBase64(await sha256(stringToBytes(publishableKey))),
  );
}

function deviceAuthenticationSigner(
  keyPair: StoredDeviceAuthentication,
  publishableKey: string,
): HostedSignalProtocolRelayDeviceAuthentication {
  return {
    publicKey: base64ToBytes(keyPair.publicKey),
    signCertificateRequest: async (tokenId, nonce) => {
      if (!tokenId || tokenId.includes('\0') || !nonce || nonce.length > 256)
        throw new Error('Signal Protocol Relay certificate request is invalid');
      return base64ToBytes(
        await sign(
          keyPair.privateKey,
          concatBytes(
            SIGNAL_RELAY_PROOF_LABELS.senderCertificateRequest,
            stringToBytes(tokenId),
            new Uint8Array([0]),
            stringToBytes(nonce),
          ),
        ),
      );
    },
    signChallenge: async (challenge) => {
      if (!(challenge instanceof Uint8Array) || challenge.length === 0) {
        throw new Error('Signal Protocol Relay device challenge must not be empty');
      }
      const payload = concatBytes(
        SIGNAL_RELAY_PROOF_LABELS.deviceAuthentication,
        stringToBytes(publishableKey),
        new Uint8Array([0]),
        challenge,
      );
      return base64ToBytes(await sign(keyPair.privateKey, payload));
    },
  };
}
