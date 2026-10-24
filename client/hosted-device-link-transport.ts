import { bytesToBase64, concatBytes, sha256, stringToBytes } from '../internal/crypto';
import type { HostedRelayManagedDeviceLinkRequest } from './hosted';

type JsonRecord = Record<string, unknown>;

function lengthPrefixed(value: Uint8Array): Uint8Array {
  const size = value.length;
  return concatBytes(new Uint8Array([size >>> 24, size >>> 16, size >>> 8, size]), value);
}

/** Compose the existing link protocol under a private current-token capability. */
export async function submitHostedRelayDeviceLink(
  request: HostedRelayManagedDeviceLinkRequest,
  protocol: {
    readonly relayScopeId: string;
    readonly materialFingerprint: string;
    readonly signalRegistration: JsonRecord;
    readonly post: (body: (tokenId: string) => Promise<JsonRecord>) => Promise<unknown>;
  },
): Promise<unknown> {
  return protocol.post(async (tokenId) => {
    const challenge = await sha256(concatBytes(
      stringToBytes('OpenE2EE Relay device link challenge v1\0'),
      ...[protocol.relayScopeId, tokenId, request.operationId, protocol.materialFingerprint]
        .map((value) => lengthPrefixed(stringToBytes(value))),
      lengthPrefixed(request.newDeviceAuthentication.publicKey),
    ));
    const [activeDeviceProof, newDeviceProof] = await Promise.all([
      request.activeDeviceAuthentication.signChallenge(challenge),
      request.newDeviceAuthentication.signChallenge(challenge),
    ]);
    return {
      publishableKey: request.publishableKey,
      operationId: request.operationId,
      signalRegistration: protocol.signalRegistration,
      newDeviceAuthenticationPublicKey: bytesToBase64(request.newDeviceAuthentication.publicKey),
      activeDeviceProof: bytesToBase64(activeDeviceProof),
      newDeviceProof: bytesToBase64(newDeviceProof),
    };
  });
}
