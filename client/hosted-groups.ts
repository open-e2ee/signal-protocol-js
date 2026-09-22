import type {
  GroupAuthorization,
  GroupChangeLogEntry,
  GroupChangeLogPage,
  GroupSnapshot,
  IGroupServer,
} from '../internal/groups/manager';
import { base64ToBytes, bytesToBase64 } from '../internal/crypto';
import type { Base64 } from '../types';
import type { HostedRelayConnection } from './hosted-connection';
import {
  isGroupErrorDetail,
  type GroupErrorDetail,
} from '../internal/groups/error-details';

const MAXIMUM_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAXIMUM_CHANGE_ENTRIES = 64;
const GROUP_ERROR_STATUS: Readonly<Record<string, number>> = {
  INVALID_REQUEST: 400,
  UNAUTHORIZED: 403,
  FORBIDDEN: 403,
  VERSION_CONFLICT: 409,
};
type JsonRecord = Record<string, unknown>;

function record(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function invalidResponse(): never {
  throw new Error('Relay returned an invalid group response');
}

function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    invalidResponse();
  return value;
}

function bytes(value: unknown): Uint8Array {
  if (typeof value !== 'string') invalidResponse();
  try {
    const result = base64ToBytes(value as Base64);
    if (bytesToBase64(result) !== value) invalidResponse();
    return result;
  } catch {
    invalidResponse();
  }
}

function change(value: unknown): GroupChangeLogEntry {
  if (!record(value)) invalidResponse();
  const result = {
    version: integer(value.version),
    actions: bytes(value.actions),
    serverSignature: bytes(value.serverSignature),
    changeEpoch: integer(value.changeEpoch),
    timestamp: integer(value.timestamp),
  };
  if (result.serverSignature.byteLength !== 64) invalidResponse();
  return result;
}

async function readResponse(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) {
    if (response.status === 204) return undefined;
    invalidResponse();
  }
  let length = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > MAXIMUM_RESPONSE_BYTES) {
        await reader.cancel();
        invalidResponse();
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  if (response.status === 204) {
    if (length !== 0) invalidResponse();
    return undefined;
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    invalidResponse();
  }
}

export class HostedGroupError extends Error {
  readonly data: {
    code: string;
    status: number;
    reason?: string;
    detail?: GroupErrorDetail;
  };

  constructor(status: number, value: unknown) {
    const error = record(value) && record(value.error) ? value.error : {};
    const code =
      typeof error.code === 'string' &&
      Object.hasOwn(GROUP_ERROR_STATUS, error.code) &&
      GROUP_ERROR_STATUS[error.code] === status
        ? error.code
        : 'GROUP_REQUEST_FAILED';
    super(`${code}: Relay group request failed`);
    this.name = 'HostedGroupError';
    this.data = { code, status };
    if (code !== 'GROUP_REQUEST_FAILED' && isGroupErrorDetail(error.detail))
      this.data.detail = error.detail;
    if (
      code === 'FORBIDDEN' &&
      typeof error.reason === 'string' &&
      ['not_readable', 'before_join', 'not_a_member'].includes(error.reason)
    )
      this.data.reason = error.reason;
  }
}

/** Presentation-authorized group state. Device credentials never enter this transport. */
export class HostedGroupServer implements IGroupServer {
  constructor(private readonly connection: HostedRelayConnection) {}

  private async request(
    operation: 'create' | 'state' | 'join-info' | 'changes' | 'change' | 'endorsements',
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    fields: JsonRecord = {},
  ): Promise<unknown> {
    if (!authorization.authorityKeyId || !/^[A-Za-z0-9_-]{1,128}$/.test(authorization.authorityKeyId))
      throw new Error('Managed group requests require a verified authority selection');
    const response = await fetch(
      `${this.connection.protocolEndpoint}/anonymous/groups/${operation}`,
      {
        method: 'POST',
        credentials: 'omit',
        redirect: 'error',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          publishableKey: this.connection.publishableKey,
          authorityKeyId: authorization.authorityKeyId,
          groupId: bytesToBase64(groupId),
          presentation: bytesToBase64(authorization.presentation),
          groupPublicParams: bytesToBase64(authorization.groupPublicParams),
          ...fields,
        }),
      },
    );
    const value = await readResponse(response);
    if (!response.ok) throw new HostedGroupError(response.status, value);
    return value;
  }

  async refreshGroupSendEndorsements(groupId: Uint8Array, authorization: GroupAuthorization): Promise<{ endorsements: Uint8Array; expiration: number }> {
    const value = await this.request('endorsements', groupId, authorization);
    if (!record(value)) invalidResponse();
    const expiration = integer(value.expiration);
    const endorsements = bytes(value.endorsements);
    if (expiration % 86400 !== 0 || endorsements.length < 1) invalidResponse();
    return { endorsements, expiration };
  }

  async createGroup(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<void> {
    const value = await this.request('create', groupId, authorization, {
      encryptedState: bytesToBase64(encryptedState),
    });
    if (value !== undefined) invalidResponse();
  }

  async getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number,
  ): Promise<GroupSnapshot | null> {
    const value = await this.request(
      'state',
      groupId,
      authorization,
      version === undefined ? {} : { version },
    );
    if (value === null) return null;
    if (!record(value)) invalidResponse();
    const result = {
      encryptedState: bytes(value.encryptedState),
      version: integer(value.version),
      baselineSignature: bytes(value.baselineSignature),
    };
    if (
      result.baselineSignature.byteLength !== 64 ||
      (version !== undefined && result.version !== version)
    )
      invalidResponse();
    return result;
  }

  async getGroupJoinInfo(
    groupId: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> {
    const value = await this.request('join-info', groupId, authorization, {
      inviteLinkPassword: bytesToBase64(inviteLinkPassword),
    });
    if (value === null) return null;
    if (!record(value)) invalidResponse();
    return {
      encryptedJoinInfo: bytes(value.encryptedJoinInfo),
      version: integer(value.version),
    };
  }

  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization,
  ): Promise<GroupChangeLogPage> {
    const value = await this.request('changes', groupId, authorization, {
      fromVersion,
    });
    if (
      !record(value) ||
      !Array.isArray(value.entries) ||
      value.entries.length > MAXIMUM_CHANGE_ENTRIES ||
      typeof value.hasMore !== 'boolean'
    )
      invalidResponse();
    const entries = value.entries.map(change);
    if (
      (value.hasMore && entries.length === 0) ||
      entries.some((entry, index) => entry.version !== fromVersion + index + 1)
    )
      invalidResponse();
    return { entries, hasMore: value.hasMore };
  }

  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<GroupChangeLogEntry> {
    if (arguments.length !== 5)
      throw new Error(
        'INVALID_REQUEST: Group change submission must not carry an epoch',
      );
    const result = change(
      await this.request('change', groupId, authorization, {
        expectedVersion,
        actions: bytesToBase64(actions),
        inviteLinkPassword: bytesToBase64(inviteLinkPassword),
      }),
    );
    if (result.version !== expectedVersion + 1) invalidResponse();
    return result;
  }
}
