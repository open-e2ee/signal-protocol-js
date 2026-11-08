/** Resume existing hosted authority without an assertion or registration fallback. */
import {
  readRetainedIdentities,
  RetainedIdentityError,
} from '../internal/manager/retained-identity';
import {
  createClientWithRetainedIdentities,
  type DefaultSignalProtocolClient,
} from './client';
import { ClientStartupCleanupError } from './startup-cleanup';
import {
  createClientFromHostedResult,
  getExistingDeviceAuthentication,
  hostedSignalProtocolRelayUrl,
  type HostedSignalProtocolClientOptions,
} from './hosted';
import { resolveHostedSignalProtocolRelayConnection } from './hosted-connection';
import { resumeHostedSignalProtocolRelayTransport } from './hosted-transport';
import { assertHostedSignalProtocolRelayProfileKeys } from './hosted-profile-keys';
import {
  HostedSignalProtocolRelayResumeError,
  retainHostedResumeCleanup,
  type HostedSignalProtocolRelayResumePhase,
  type HostedSignalProtocolRelayResumeProgressCallback,
} from './hosted-resume-error';

/** Existing hosted options without any registration/assertion authority. */
export type HostedSignalProtocolResumeOptions = Omit<
  HostedSignalProtocolClientOptions,
  'adapters' | 'hosted'
> & {
  readonly adapters: Omit<
    HostedSignalProtocolClientOptions['adapters'],
    'protocolManager'
  > & { readonly protocolManager?: never };
  readonly hosted: Omit<
    HostedSignalProtocolClientOptions['hosted'],
    'getIdentityAssertion' | 'assertionPurpose' | 'assurance' | 'onProgress'
  > & {
    readonly getIdentityAssertion?: never;
    readonly assertionPurpose?: never;
    readonly assurance?: never;
    readonly onProgress?: HostedSignalProtocolRelayResumeProgressCallback;
  };
};

/**
 * Require the existing permanent identities, device key and scoped hosted session.
 * Renews the token and starts the ordinary client, including prekey maintenance and
 * automatic subscription. Never requests assertions or registers a replacement.
 * The caller owns the already-open store and must not use it concurrently.
 * On an unresolved stop, the thrown HostedSignalProtocolRelayResumeError owns retryCleanup().
 */
export async function resumeHostedSignalProtocolClient(
  options: HostedSignalProtocolResumeOptions,
): Promise<DefaultSignalProtocolClient> {
  const { adapters, hosted, ...clientOptions } = options;
  if (
    adapters.protocolManager !== undefined ||
    ['getIdentityAssertion', 'assertionPurpose', 'assurance'].some((key) =>
      Object.hasOwn(hosted, key),
    )
  ) {
    throw new TypeError(
      'Strict hosted resume does not accept registration options or a custom protocol manager.',
    );
  }
  if (hosted.profileKeys !== undefined)
    assertHostedSignalProtocolRelayProfileKeys(hosted.profileKeys);
  let phase: HostedSignalProtocolRelayResumePhase = 'reading-local-state';
  let captured: DefaultSignalProtocolClient | undefined;
  const progress = (next: HostedSignalProtocolRelayResumePhase) => {
    phase = next;
    hosted.onProgress?.({ phase });
  };
  try {
    progress('reading-local-state');
    // Hosted composition activates ACI. The manager checks all actual active types.
    const identities = await readRetainedIdentities(adapters.storage, ['aci']);
    const connection = await resolveHostedSignalProtocolRelayConnection(
      hostedSignalProtocolRelayUrl(hosted, 'resumeHostedSignalProtocolClient'),
    );
    const deviceAuthentication = await getExistingDeviceAuthentication(
      adapters.storage,
      connection.publishableKey,
      true,
    );
    const resumed = await resumeHostedSignalProtocolRelayTransport({
      connection,
      deviceAuthentication,
      storage: adapters.storage,
      requireExisting: true,
      onAuthenticating: () => progress('authenticating'),
    });
    if (!resumed)
      throw new HostedSignalProtocolRelayResumeError(
        'RETAINED_SESSION_UNAVAILABLE',
        'reading-local-state',
      );
    progress('initializing');
    const client = await createClientFromHostedResult(
      resumed,
      connection,
      adapters,
      clientOptions,
      hosted.sealedSenderAccessMode,
      resumed.remoteObjectStore,
      resumed.transport,
      hosted.profileKeys,
      async (userId, config) => {
        captured = await createClientWithRetainedIdentities(
          userId,
          config,
          identities,
        );
        return captured;
      },
    );
    if (client.syncStatus === 'failed')
      throw new Error(
        'OpenE2EE Signal Protocol Relay initial synchronization failed',
      );
    progress('complete');
    return client;
  } catch (caught) {
    let failure = caught;
    if (captured) {
      try {
        await captured.stop();
      } catch (cleanupFailure) {
        failure = new ClientStartupCleanupError(caught, cleanupFailure, () =>
          captured!.stop(),
        );
      }
    }
    if (failure instanceof ClientStartupCleanupError) {
      const error = new HostedSignalProtocolRelayResumeError(
        'RESUME_CLEANUP_UNRESOLVED',
        phase,
        { cause: failure.failure },
      );
      retainHostedResumeCleanup(error, failure.retryCleanup);
      throw error;
    }
    if (failure instanceof RetainedIdentityError) {
      const code =
        failure.reason === 'changed'
          ? 'RETAINED_IDENTITY_CHANGED'
          : failure.reason === 'unreadable'
            ? 'RETAINED_STATE_UNREADABLE'
            : 'RETAINED_IDENTITY_UNAVAILABLE';
      throw new HostedSignalProtocolRelayResumeError(code, phase, { cause: failure });
    }
    throw failure;
  }
}
