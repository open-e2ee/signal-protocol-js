import { bytesToBase64, concatBytes, sha256, stringToBytes } from '../internal/crypto';
import type { HostedSignalProtocolRelayManagedDeviceLinkRequest } from './hosted';
import { signalRelayProofLabels } from './signal-relay-protocol';

type JsonRecord = Record<string, unknown>;

function lengthPrefixed(value: Uint8Array): Uint8Array {
  const size = value.length;
  return concatBytes(new Uint8Array([size >>> 24, size >>> 16, size >>> 8, size]), value);
}

/**
 * Compose the existing link protocol under a private current-token
 * capability. `post` gives the body the token ID and the Relay protocol
 * version of the request, which selects the labels of the two proofs.
 */
export async function submitHostedSignalProtocolRelayDeviceLink(
  request: HostedSignalProtocolRelayManagedDeviceLinkRequest,
  protocol: {
    readonly relayScopeId: string;
    readonly materialFingerprint: string;
    readonly signalRegistration: JsonRecord;
    readonly post: (body: (tokenId: string, protocolVersion: number) => Promise<JsonRecord>) => Promise<unknown>;
  },
): Promise<unknown> {
  return protocol.post(async (tokenId, protocolVersion) => {
    const challenge = await sha256(concatBytes(
      signalRelayProofLabels(protocolVersion).deviceLinkChallenge,
      ...[protocol.relayScopeId, tokenId, request.operationId, protocol.materialFingerprint]
        .map((value) => lengthPrefixed(stringToBytes(value))),
      lengthPrefixed(request.newDeviceAuthentication.publicKey),
    ));
    const [activeDeviceProof, newDeviceProof] = await Promise.all([
      request.activeDeviceAuthentication.signChallenge(challenge, protocolVersion),
      request.newDeviceAuthentication.signChallenge(challenge, protocolVersion),
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
