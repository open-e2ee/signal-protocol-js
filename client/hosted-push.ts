import type { SignalProtocolClient } from './client';
import type { IncomingEnvelope, ProcessEnvelopeOptions } from './types';

const PUSH_TOKEN_MAXIMUM_LENGTH = 4_096;
const PUSH_ENDPOINT_MAXIMUM_LENGTH = 2_048;

/** Native or Expo provider token registered for this authenticated device. */
export type HostedRelayTokenPushRegistration = {
  readonly provider: 'apns' | 'expo' | 'fcm';
  readonly token: string;
};

/** Browser Push API subscription registered for this authenticated device. */
export interface HostedRelayWebPushRegistration {
  readonly endpoint: string;
  readonly keys: {
    readonly auth: string;
    readonly p256dh: string;
  };
  readonly provider: 'web-push';
}

/** Supported data-only wake registration shapes. */
export type HostedRelayPushRegistration =
  HostedRelayTokenPushRegistration | HostedRelayWebPushRegistration;

export interface HostedRelayPushRegistrationRequest {
  readonly publishableKey: string;
  readonly registration: HostedRelayPushRegistration;
}

export interface HostedRelayPushRemovalRequest {
  readonly publishableKey: string;
}

export interface HostedRelayMailboxPullRequest {
  readonly publishableKey: string;
}

export interface HostedRelayMailboxAcknowledgmentRequest {
  readonly messageIds: readonly string[];
  readonly publishableKey: string;
}

/**
 * Authenticated hosted transport for wake registration and durable mailbox pull.
 *
 * The adapter owns the device credential. These request shapes do not accept an
 * account, device, scope, or generation because the Relay derives those fields
 * from that credential.
 */
export interface HostedRelayPushAdapter {
  acknowledgeMailbox(
    request: HostedRelayMailboxAcknowledgmentRequest
  ): Promise<void>;
  pullMailbox(
    request: HostedRelayMailboxPullRequest
  ): Promise<readonly IncomingEnvelope[]>;
  registerPush(request: HostedRelayPushRegistrationRequest): Promise<void>;
  removePush(request: HostedRelayPushRemovalRequest): Promise<void>;
}

export interface HostedRelayWakeClient {
  processIncomingEnvelopes(
    envelopes: IncomingEnvelope[],
    options?: ProcessEnvelopeOptions
  ): ReturnType<SignalProtocolClient['processIncomingEnvelopes']>;
}

export interface HostedRelayWakeOptions {
  readonly adapter: HostedRelayPushAdapter;
  readonly client: HostedRelayWakeClient;
  readonly processOptions?: ProcessEnvelopeOptions;
  readonly publishableKey: string;
}

export interface HostedRelayWakeResult {
  readonly acknowledgedMessageIds: readonly string[];
  readonly failedMessageIds: readonly string[];
  readonly pulled: number;
}

function assertPublishableKey(value: string): string {
  const publishableKey = value.trim();
  if (!publishableKey || publishableKey.length > 512) {
    throw new Error('Hosted Relay publishable key is invalid');
  }
  return publishableKey;
}

function assertToken(token: string): string {
  if (!token || token.length > PUSH_TOKEN_MAXIMUM_LENGTH) {
    throw new Error('Hosted Relay push token is invalid');
  }
  return token;
}

function validatedRegistration(
  registration: HostedRelayPushRegistration
): HostedRelayPushRegistration {
  if (registration.provider !== 'web-push') {
    return {
      provider: registration.provider,
      token: assertToken(registration.token),
    };
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
    provider: 'web-push',
  };
}

/** Register a data-only wake destination for the adapter's authenticated device. */
export async function registerHostedRelayPush(options: {
  readonly adapter: HostedRelayPushAdapter;
  readonly publishableKey: string;
  readonly registration: HostedRelayPushRegistration;
}): Promise<void> {
  await options.adapter.registerPush({
    publishableKey: assertPublishableKey(options.publishableKey),
    registration: validatedRegistration(options.registration),
  });
}

/** Remove the data-only wake destination for the adapter's authenticated device. */
export async function removeHostedRelayPush(options: {
  readonly adapter: HostedRelayPushAdapter;
  readonly publishableKey: string;
}): Promise<void> {
  await options.adapter.removePush({
    publishableKey: assertPublishableKey(options.publishableKey),
  });
}

/**
 * Authenticate, pull the durable mailbox, process each envelope, and acknowledge
 * only successful decryptions. This operation is safe to call after repeated
 * wake hints and can also be called when push is unavailable.
 */
export async function pullHostedRelayAfterWake(
  options: HostedRelayWakeOptions
): Promise<HostedRelayWakeResult> {
  const publishableKey = assertPublishableKey(options.publishableKey);
  const envelopes = await options.adapter.pullMailbox({ publishableKey });
  const results = await options.client.processIncomingEnvelopes(
    [...envelopes],
    options.processOptions
  );
  if (results.length !== envelopes.length) {
    throw new Error(
      'Hosted Relay mailbox processing returned an invalid result'
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
    await options.adapter.acknowledgeMailbox({
      messageIds: acknowledgedMessageIds,
      publishableKey,
    });
  }
  return {
    acknowledgedMessageIds,
    failedMessageIds,
    pulled: envelopes.length,
  };
}
