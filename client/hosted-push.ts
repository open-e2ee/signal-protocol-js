import type { SignalProtocolClient } from './client';
import type { IncomingEnvelope, ProcessEnvelopeOptions } from './types';

const PUSH_TOKEN_MAXIMUM_LENGTH = 4_096;
const PUSH_ENDPOINT_MAXIMUM_LENGTH = 2_048;

export type HostedRelayPushProfile =
  'background-only' | 'visible-alert' | 'nse-visible' | 'nse-filtering';

export type HostedRelayPushPlatform = 'android' | 'ios' | 'web';

/** Native or Expo provider token registered for this authenticated device. */
export type HostedRelayTokenPushRegistration =
  | {
      readonly platform: 'ios';
      readonly profile: HostedRelayPushProfile;
      readonly provider: 'apns' | 'expo';
      readonly token: string;
    }
  | {
      readonly platform: 'android';
      readonly profile: 'background-only' | 'visible-alert';
      readonly provider: 'expo' | 'fcm';
      readonly token: string;
    };

/** Browser Push API subscription registered for this authenticated device. */
export interface HostedRelayWebPushRegistration {
  readonly endpoint: string;
  readonly keys: {
    readonly auth: string;
    readonly p256dh: string;
  };
  readonly platform: 'web';
  readonly profile: 'background-only' | 'visible-alert';
  readonly provider: 'web-push';
}

/** Supported best-effort wake and generic-alert registration shapes. */
export type HostedRelayPushRegistration =
  HostedRelayTokenPushRegistration | HostedRelayWebPushRegistration;

/** @internal SDK-owned transport for one authenticated hosted client. */
export interface HostedRelayPushRuntime {
  acknowledgeMailbox(messageIds: readonly string[]): Promise<void>;
  pullMailbox(): Promise<readonly IncomingEnvelope[]>;
  registerPush(registration: HostedRelayPushRegistration): Promise<void>;
  removePush(): Promise<void>;
}

export interface HostedRelayWakeClient {
  processIncomingEnvelopes(
    envelopes: IncomingEnvelope[],
    options?: ProcessEnvelopeOptions,
  ): ReturnType<SignalProtocolClient['processIncomingEnvelopes']>;
}

export interface HostedRelayWakeOptions {
  readonly client: HostedRelayWakeClient;
  readonly processOptions?: ProcessEnvelopeOptions;
}

export interface HostedRelayWakeResult {
  readonly acknowledgedMessageIds: readonly string[];
  readonly failedMessageIds: readonly string[];
  readonly pulled: number;
}

const hostedRuntimes = new WeakMap<object, HostedRelayPushRuntime>();

/** @internal Bind the SDK-owned transport to the client that uses it. */
export function bindHostedRelayPushRuntime(
  client: HostedRelayWakeClient,
  runtime: HostedRelayPushRuntime,
): void {
  hostedRuntimes.set(client, runtime);
}

function hostedRuntime(client: HostedRelayWakeClient): HostedRelayPushRuntime {
  const runtime = hostedRuntimes.get(client);
  if (runtime === undefined) {
    throw new Error('The client is not connected to OpenE2EE Relay');
  }
  return runtime;
}

function assertToken(token: string): string {
  if (!token || token.length > PUSH_TOKEN_MAXIMUM_LENGTH) {
    throw new Error('Hosted Relay push token is invalid');
  }
  return token;
}

function validatedRegistration(
  registration: HostedRelayPushRegistration,
): HostedRelayPushRegistration {
  if (
    registration.profile !== 'background-only' &&
    registration.profile !== 'visible-alert' &&
    registration.profile !== 'nse-visible' &&
    registration.profile !== 'nse-filtering'
  ) {
    throw new Error('Hosted Relay push profile is invalid');
  }
  if (registration.profile === 'nse-filtering') {
    throw new Error(
      'Hosted Relay notification filtering is unavailable until signed physical-device verification passes',
    );
  }
  if (registration.provider !== 'web-push') {
    if (
      (registration.provider === 'apns' && registration.platform !== 'ios') ||
      (registration.provider === 'fcm' &&
        registration.platform !== 'android') ||
      (registration.provider === 'expo' &&
        registration.platform !== 'ios' &&
        registration.platform !== 'android') ||
      (registration.platform !== 'ios' &&
        registration.profile !== 'background-only' &&
        registration.profile !== 'visible-alert')
    ) {
      throw new Error(
        'Hosted Relay push profile is not supported by this platform',
      );
    }
    return {
      ...registration,
      token: assertToken(registration.token),
    };
  }
  if (
    registration.platform !== 'web' ||
    (registration.profile !== 'background-only' &&
      registration.profile !== 'visible-alert')
  ) {
    throw new Error(
      'Hosted Relay push profile is not supported by this platform',
    );
  }
  let endpoint: URL;
  try {
    endpoint = new URL(registration.endpoint);
  } catch {
    throw new Error('Hosted Relay Web Push endpoint is invalid');
  }
  if (
    endpoint.protocol !== 'https:' ||
    registration.endpoint.length > PUSH_ENDPOINT_MAXIMUM_LENGTH
  ) {
    throw new Error('Hosted Relay Web Push endpoint is invalid');
  }
  return {
    endpoint: registration.endpoint,
    keys: {
      auth: assertToken(registration.keys.auth),
      p256dh: assertToken(registration.keys.p256dh),
    },
    platform: registration.platform,
    profile: registration.profile,
    provider: 'web-push',
  };
}

/** Register a best-effort wake profile for this hosted client's device. */
export async function registerHostedRelayPush(options: {
  readonly client: HostedRelayWakeClient;
  readonly registration: HostedRelayPushRegistration;
}): Promise<void> {
  const registration = validatedRegistration(options.registration);
  await hostedRuntime(options.client).registerPush(registration);
}

/** Remove the wake destination for this hosted client's device. */
export async function removeHostedRelayPush(options: {
  readonly client: HostedRelayWakeClient;
}): Promise<void> {
  await hostedRuntime(options.client).removePush();
}

/**
 * Authenticate, pull the durable mailbox, process each envelope, and acknowledge
 * only successful decryptions. This operation is safe to call after repeated
 * wake hints and can also be called when push is unavailable.
 */
export async function pullHostedRelayAfterWake(
  options: HostedRelayWakeOptions,
): Promise<HostedRelayWakeResult> {
  const runtime = hostedRuntime(options.client);
  const envelopes = await runtime.pullMailbox();
  const results = await options.client.processIncomingEnvelopes(
    [...envelopes],
    options.processOptions,
  );
  if (results.length !== envelopes.length) {
    throw new Error(
      'Hosted Relay mailbox processing returned an invalid result',
    );
  }
  const acknowledgedMessageIds: string[] = [];
  const failedMessageIds: string[] = [];
  for (const result of results) {
    if ('plaintext' in result) {
      acknowledgedMessageIds.push(result.envelope.id);
    } else {
      failedMessageIds.push(result.envelope.id);
    }
  }
  if (acknowledgedMessageIds.length > 0) {
    await runtime.acknowledgeMailbox(acknowledgedMessageIds);
  }
  return {
    acknowledgedMessageIds,
    failedMessageIds,
    pulled: envelopes.length,
  };
}
