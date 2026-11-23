/** The client composition of a hosted bootstrap, link or resume result. */
import { base64ToBytes, bytesToUrlSafeBase64, urlSafeToBase64 } from '../internal/crypto';
import { resolveSignalProtocolLogger } from '../logger';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { Base64 } from '../types';
import { DefaultSignalProtocolClient } from './client';
import type { SignalProtocolClientCompositionOptions } from './compose';
import { createSignalProtocolClientConfig } from './compose';
import type { SealedSenderAccessMode } from './config';
import type {
  HostedSignalProtocolClientOptions,
  HostedSignalProtocolRelayBootstrapResult,
} from './hosted';
import type {
  HostedSignalProtocolRelayCertificateTrust,
  HostedSignalProtocolRelayConnection,
} from './hosted-connection';
import { bindHostedSignalProtocolRelayDeviceManagementRuntime } from './hosted-device-management';
import { resolveHostedGroupOptions } from './hosted-group-authority';
import { bindHostedSignalProtocolRelayPresenceRuntime } from './hosted-presence';
import {
  bindHostedSignalProtocolRelayProfileKeys,
  hostedSealedSenderContacts,
  type HostedSignalProtocolRelayProfileKeys,
} from './hosted-profile-keys';
import { bindHostedSignalProtocolRelayPushRuntime } from './hosted-push';
import type { HostedSignalProtocolRelayTransportResult } from './hosted-transport';
import { createKeyTransparencyRuntime } from './key-transparency/runtime';
import { identityLogTrustOf } from './key-transparency/trust';

function assertHostedBootstrapResult(
  result: HostedSignalProtocolRelayBootstrapResult,
  certificateTrust: HostedSignalProtocolRelayCertificateTrust,
): void {
  if (!result.canonicalAccountId || result.canonicalAccountId.length > 512) {
    throw new Error(
      'Signal Protocol Relay returned an invalid canonical account binding',
    );
  }
  if (!Number.isSafeInteger(result.deviceId) || result.deviceId < 1) {
    throw new Error('Signal Protocol Relay returned an invalid device binding');
  }
  if (
    !(result.relayScopeId instanceof Uint8Array) ||
    result.relayScopeId.length !== 16
  ) {
    throw new Error(
      'Signal Protocol Relay returned an invalid project-environment scope',
    );
  }
  if (!result.relay) {
    throw new Error(
      'Signal Protocol Relay bootstrap did not return an authenticated Relay',
    );
  }
  if (certificateTrust.trustRoots.length === 0) {
    throw new Error('Signal Protocol Relay has no compiled certificate root');
  }
  for (const root of certificateTrust.trustRoots) {
    if (!(root instanceof Uint8Array) || root.length !== 32) {
      throw new Error('Signal Protocol Relay has an invalid compiled certificate root');
    }
  }
  for (const keyId of certificateTrust.revokedIssuerKeyIds) {
    if (!Number.isSafeInteger(keyId) || keyId < 0 || keyId > 0xffff_ffff) {
      throw new Error('Signal Protocol Relay has an invalid revoked issuer key ID');
    }
  }
}

function hostedAccountAci(accountId: string) {
  if (!/^[A-Za-z0-9_-]{22}$/u.test(accountId)) {
    throw new Error('Signal Protocol Relay returned an invalid account ACI');
  }
  let uuid: Uint8Array;
  try {
    uuid = base64ToBytes(urlSafeToBase64(accountId) as Base64);
  } catch {
    throw new Error('Signal Protocol Relay returned an invalid account ACI');
  }
  if (
    uuid.length !== 16 ||
    uuid.every((byte) => byte === 0) ||
    bytesToUrlSafeBase64(uuid) !== accountId
  ) {
    throw new Error('Signal Protocol Relay returned an invalid account ACI');
  }
  return { kind: 0 as const, uuid };
}

/** @internal Shared hosted composition; caller retains failure cleanup custody. */
export async function createClientFromHostedResult(
  result: HostedSignalProtocolRelayBootstrapResult,
  connection: HostedSignalProtocolRelayConnection,
  adapters: Omit<
    SignalProtocolClientCompositionOptions['adapters'],
    'relay' | 'remoteObjectStore'
  >,
  clientOptions: Omit<
    HostedSignalProtocolClientOptions,
    'adapters' | 'hosted'
  >,
  sealedSenderAccessMode?: SealedSenderAccessMode,
  remoteObjectStore?: SignalProtocolRemoteObjectStore,
  hostedTransport?: HostedSignalProtocolRelayTransportResult['transport'],
  profileKeys?: HostedSignalProtocolRelayProfileKeys,
  createClient: typeof DefaultSignalProtocolClient.create = DefaultSignalProtocolClient.create,
): Promise<DefaultSignalProtocolClient> {
  const { certificateTrust } = connection;
  assertHostedBootstrapResult(result, certificateTrust);
  const { groups, ...rest } = clientOptions;
  const aci =
    groups === undefined
      ? undefined
      : hostedAccountAci(result.canonicalAccountId);
  const resolvedGroups =
    groups === undefined
      ? undefined
      : await resolveHostedGroupOptions(connection, groups);
  const config = createSignalProtocolClientConfig({
    ...rest,
    ...(resolvedGroups
      ? {
          groups: {
            ...resolvedGroups,
            resolveAciBytesByUserIds: async (userIds: string[]) =>
              new Map(
                userIds.map((userId) => [
                  userId,
                  hostedAccountAci(userId).uuid,
                ]),
              ),
          },
        }
      : {}),
    adapters: {
      ...adapters,
      relay: result.relay,
      ...(remoteObjectStore === undefined ? {} : { remoteObjectStore }),
    },
    identity: {
      userId: result.canonicalAccountId,
      deviceId: result.deviceId,
      ...(aci === undefined ? {} : { aci }),
    },
    sealedSender: {
      accessMode: sealedSenderAccessMode,
      relayScopeId: result.relayScopeId,
      revokedIssuerKeyIds: certificateTrust.revokedIssuerKeyIds,
      trustModel: 'hosted',
      trustRoots: certificateTrust.trustRoots.map(
        (root) => new Uint8Array(root),
      ),
      ...(profileKeys === undefined
        ? {}
        : { contactStateStore: hostedSealedSenderContacts(profileKeys.contacts) }),
    },
  });
  const client = await createClient(result.canonicalAccountId, config);
  if (hostedTransport !== undefined) {
    bindHostedSignalProtocolRelayPushRuntime(client, hostedTransport);
    bindHostedSignalProtocolRelayPresenceRuntime(client, hostedTransport);
    bindHostedSignalProtocolRelayDeviceManagementRuntime(client, { transport: hostedTransport, connection, storage: adapters.storage, groupStore: groups?.store, logger: resolveSignalProtocolLogger(config.logger) });
    const transport = hostedTransport;
    client.attachKeyTransparency((report) =>
      createKeyTransparencyRuntime({
        trust: identityLogTrustOf(connection),
        environment: connection.environment,
        scope: transport.identityLogScope,
        ownUserId: result.canonicalAccountId,
        store: adapters.storage,
        transport,
        report,
        logger: resolveSignalProtocolLogger(config.logger),
      }),
    );
    if (profileKeys !== undefined)
      bindHostedSignalProtocolRelayProfileKeys(
        client,
        hostedTransport,
        profileKeys,
        resolveSignalProtocolLogger(config.logger),
      );
  }
  return client;
}
