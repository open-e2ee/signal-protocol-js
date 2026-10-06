import { utf8Decode } from '../internal/platform';
import type { SignalProtocolClientCompositionOptions } from './compose';
import type { HostedRelayConnection } from './hosted-connection';
import { withRelayRequestDeadline } from './relay-request-deadline';
import {
  EndorsementManager,
  type EndorsementCacheStore,
} from './endorsement-manager';
import { verifyGroupAuthority } from '../internal/groups/authority-certificate';
import { decodeGroupTrustRoot } from '../internal/groups/trust-root';
import type { GroupAuthority } from './group-authority';

type GroupOptions = NonNullable<
  SignalProtocolClientCompositionOptions['groups']
>;
export type HostedGroupOptions = Pick<GroupOptions, 'profileKey' | 'store'> & {
  readonly endorsementCache?: EndorsementCacheStore;
};

async function fetchAuthority(connection: HostedRelayConnection) {
  const buffer = await withRelayRequestDeadline(async (signal) => {
    const response = await fetch(
      `${connection.protocolEndpoint}/groups/authority`,
      {
        method: 'POST',
        credentials: 'omit',
        redirect: 'error',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({ publishableKey: connection.publishableKey }),
        signal,
      }
    );
    if (!response.ok || !response.body) {
      await response.body?.cancel();
      throw new Error('Managed group authority is unavailable');
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.length;
        if (length > 8192) {
          await reader.cancel();
          throw new Error('Managed group authority exceeds its size limit');
        }
        chunks.push(part.value);
      }
    } finally {
      reader.releaseLock();
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const part of chunks) {
      body.set(part, offset);
      offset += part.length;
    }
    return body;
  });
  return verifyGroupAuthority(
    JSON.parse(utf8Decode(buffer, { fatal: true })),
    {
      ...connection.certificateTrust,
      relayScopeId: connection.relayScopeId,
      nowMilliseconds: Date.now(),
    }
  );
}

/** Managed group keys come from a signed response under the compiled environment root. */
export async function resolveHostedGroupOptions(
  connection: HostedRelayConnection,
  options: HostedGroupOptions
): Promise<GroupOptions> {
  if (
    Object.keys(options).some(
      (key) => !['profileKey', 'store', 'endorsementCache'].includes(key)
    )
  )
    throw new Error(
      'Hosted group configuration cannot override managed authority'
    );
  let current:
    { value: GroupAuthority; notBefore: number; notAfter: number } | undefined;
  let pending: Promise<GroupAuthority> | undefined;
  const resolveAuthority = async (): Promise<GroupAuthority> => {
    const now = Date.now();
    if (current && now >= current.notBefore && now < current.notAfter)
      return current.value;
    if (pending) return pending;
    pending = (async () => {
      const authority = await fetchAuthority(connection);
      const root = decodeGroupTrustRoot(authority.trustRoot);
      const value: GroupAuthority = {
        trustRoot: authority.trustRoot,
        authorityKeyId: authority.keyId,
        ...(options.endorsementCache === undefined
          ? {}
          : {
              endorsementManager: new EndorsementManager(
                options.endorsementCache,
                root.endorsementRootPublicKey
              ),
            }),
      };
      current = {
        value,
        notBefore: authority.notBeforeMilliseconds,
        notAfter: authority.notAfterMilliseconds,
      };
      return value;
    })();
    try {
      return await pending;
    } finally {
      pending = undefined;
    }
  };
  const authority = await resolveAuthority();
  return {
    ...authority,
    resolveAuthority,
    profileKey: options.profileKey,
    ...(options.store === undefined ? {} : { store: options.store }),
  };
}
