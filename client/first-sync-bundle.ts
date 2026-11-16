/**
 * The first-sync bundle of a device link (wire contract section 11.4): the
 * snapshot that device 1 gives a newly linked own device, the checks of the
 * bundle, and the apply-once record of the receiving device.
 *
 * The send and the receive use the same checks. This module imports no
 * client module, so the cipher and the hosted call can both use it.
 */
import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  generateRandomBytesSync,
  urlSafeToBase64,
} from '../internal/crypto';
import type { Logger } from '../logger';
import type { SignalProtocolLocalStore } from '../types';
import { asBase64 } from '../types/utils';

/** A contact of a first-sync bundle. */
export interface HostedSignalProtocolRelayFirstSyncContact {
  /** Not empty. Unique in one bundle. */
  readonly userId: string;
  /** The profile key of the contact. 32 bytes. */
  readonly profileKey?: Uint8Array;
  /** Opaque to the SDK. */
  readonly applicationData?: Uint8Array;
}

/**
 * The snapshot that device 1 gives a newly linked own device.
 *
 * The bundle has at least one part. Each part is a full snapshot of its
 * kind: a part that is present replaces that kind on the new device, and an
 * empty array clears it. A part that is absent keeps that kind unchanged.
 * The SDK reads no part from its own stores.
 */
export interface HostedSignalProtocolRelayFirstSyncBundle {
  /** The own profile key. 32 bytes. */
  readonly profileKey?: Uint8Array;
  readonly settings?: {
    readonly readReceipts: boolean;
    readonly typingIndicators: boolean;
  };
  readonly contacts?: readonly HostedSignalProtocolRelayFirstSyncContact[];
  readonly blocked?: readonly {
    /** Not empty. Unique in one bundle. */
    readonly recipientId: string;
    /** Milliseconds since the Unix epoch. A non-negative safe integer. */
    readonly blockedAt: number;
  }[];
  /** Opaque to the SDK. */
  readonly applicationData?: Uint8Array;
}

/**
 * Called on a newly linked device with each new first-sync bundle from
 * device 1. The device writes the apply-once record of the bundle after the
 * callback resolves. When the callback throws or rejects, the device writes
 * no record, and the durable local receive queue gives the bundle again,
 * also after a restart. The Relay acknowledgment follows the local commit of
 * the message, before the callback, so the Relay does not deliver the bundle
 * again. A crash after the callback and before the record write also gives
 * one more call with the same bundle, so apply each part as a full replace.
 */
export type HostedSignalProtocolRelayFirstSyncCallback = (
  bundle: HostedSignalProtocolRelayFirstSyncBundle,
  details: {
    readonly bundleId: string;
    readonly senderDeviceId: number;
    readonly createdAt: Date;
  },
) => void | Promise<void>;

/**
 * The first-sync bundle with the fields that the SDK adds: the version, the
 * bundle ID, and the creation time on device 1.
 */
export interface FirstSyncInput extends HostedSignalProtocolRelayFirstSyncBundle {
  readonly version: 1;
  /** 16 random bytes, as base64url with no padding: 22 characters. */
  readonly bundleId: string;
  /** Milliseconds since the Unix epoch, by the clock of device 1. */
  readonly createdAt: number;
}

/**
 * The early content check, in bytes: the SDK refuses larger serialized
 * first-sync content before the encryption. It is not a size that fits.
 * Content of this size or less can still give a delivery wire above
 * {@link FIRST_SYNC_DELIVERY_WIRE_MAXIMUM_BYTES}.
 */
export const FIRST_SYNC_CONTENT_MAXIMUM_BYTES = 196_608;
/**
 * The serialized content size, in bytes, that fits in the first message to
 * a new device. That message opens the session, so it carries the PQXDH
 * material. The delivery wire holds the encoded ciphertext, so it is about
 * 1.8 times the content. Content of 140,000 bytes gives a wire of about
 * 252,600 bytes. A build-time test sends content of this size to a new
 * session and checks the delivery wire.
 */
export const FIRST_SYNC_DOCUMENTED_CONTENT_BYTES = 140_000;
/**
 * The largest delivery wire of a first-sync copy, in bytes. It is the
 * inline payload limit of the Relay.
 */
export const FIRST_SYNC_DELIVERY_WIRE_MAXIMUM_BYTES = 262_144;

const PROFILE_KEY_BYTES = 32;
const BUNDLE_ID_BYTES = 16;
/** The device that sends a first sync: the primary device. */
const FIRST_SYNC_SENDER_DEVICE_ID = 1;
const BUNDLE_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/u;
/** The number of applied bundle IDs that the apply-once record keeps. */
const APPLIED_BUNDLE_IDS_MAXIMUM = 32;
const FIRST_SYNC_RECORD_METADATA_KEY = 'first-sync:v1';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isOptionalBytes(value: unknown): boolean {
  return value === undefined || value instanceof Uint8Array;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/** Throw a `TypeError` for the first value of the bundle that has the wrong type. */
function checkFirstSyncBundleTypes(bundle: unknown): void {
  if (!isRecord(bundle)) throw new TypeError('The first-sync bundle must be an object.');
  if (!isOptionalBytes(bundle.profileKey)) {
    throw new TypeError('The first-sync profileKey must be a Uint8Array.');
  }
  if (!isOptionalBytes(bundle.applicationData)) {
    throw new TypeError('The first-sync applicationData must be a Uint8Array.');
  }
  const settings = bundle.settings;
  if (
    settings !== undefined &&
    (!isRecord(settings) ||
      typeof settings.readReceipts !== 'boolean' ||
      typeof settings.typingIndicators !== 'boolean')
  ) {
    throw new TypeError(
      'The first-sync settings must be an object with the booleans readReceipts and typingIndicators.',
    );
  }
  const contacts = bundle.contacts;
  if (contacts !== undefined) {
    if (!Array.isArray(contacts)) throw new TypeError('The first-sync contacts must be an array.');
    for (const contact of contacts as unknown[]) {
      if (
        !isRecord(contact) ||
        typeof contact.userId !== 'string' ||
        !isOptionalBytes(contact.profileKey) ||
        !isOptionalBytes(contact.applicationData)
      ) {
        throw new TypeError(
          'Each first-sync contact must be an object with a string userId and optional Uint8Array profileKey and applicationData.',
        );
      }
    }
  }
  const blocked = bundle.blocked;
  if (blocked !== undefined) {
    if (!Array.isArray(blocked)) throw new TypeError('The first-sync blocked list must be an array.');
    for (const entry of blocked as unknown[]) {
      if (!isRecord(entry) || typeof entry.recipientId !== 'string' || typeof entry.blockedAt !== 'number') {
        throw new TypeError(
          'Each first-sync blocked entry must be an object with a string recipientId and a number blockedAt.',
        );
      }
    }
  }
}

/** Throw a `RangeError` for the first value of a well-typed bundle that is out of range. */
function checkFirstSyncBundleRanges(bundle: HostedSignalProtocolRelayFirstSyncBundle): void {
  if (
    bundle.profileKey === undefined &&
    bundle.settings === undefined &&
    bundle.contacts === undefined &&
    bundle.blocked === undefined &&
    bundle.applicationData === undefined
  ) {
    throw new RangeError(
      'The first-sync bundle must have at least one of profileKey, settings, contacts, blocked, and applicationData.',
    );
  }
  if (bundle.profileKey !== undefined && bundle.profileKey.length !== PROFILE_KEY_BYTES) {
    throw new RangeError('The first-sync profileKey must be 32 bytes.');
  }
  const userIds = new Set<string>();
  for (const contact of bundle.contacts ?? []) {
    if (contact.userId === '') throw new RangeError('A first-sync contact userId must not be empty.');
    if (userIds.has(contact.userId)) {
      throw new RangeError('Each first-sync contact userId must be unique in the bundle.');
    }
    userIds.add(contact.userId);
    if (contact.profileKey !== undefined && contact.profileKey.length !== PROFILE_KEY_BYTES) {
      throw new RangeError('A first-sync contact profileKey must be 32 bytes.');
    }
  }
  const recipientIds = new Set<string>();
  for (const entry of bundle.blocked ?? []) {
    if (entry.recipientId === '') throw new RangeError('A first-sync blocked recipientId must not be empty.');
    if (recipientIds.has(entry.recipientId)) {
      throw new RangeError('Each first-sync blocked recipientId must be unique in the bundle.');
    }
    recipientIds.add(entry.recipientId);
    if (!isNonNegativeSafeInteger(entry.blockedAt)) {
      throw new RangeError('A first-sync blockedAt must be a non-negative safe integer.');
    }
  }
}

/**
 * Check a first-sync bundle. Each type check runs before each range check,
 * so a bundle with both faults gives the `TypeError`.
 *
 * @throws TypeError for a value of the wrong type
 * @throws RangeError for a bundle with no part, a profile key that is not
 *   32 bytes, an empty or repeated `userId` or `recipientId`, or a
 *   `blockedAt` that is not a non-negative safe integer
 */
export function checkFirstSyncBundle(
  bundle: unknown,
): asserts bundle is HostedSignalProtocolRelayFirstSyncBundle {
  checkFirstSyncBundleTypes(bundle);
  checkFirstSyncBundleRanges(bundle as HostedSignalProtocolRelayFirstSyncBundle);
}

/** True for 22 base64url characters that are the canonical form of 16 bytes. */
export function isFirstSyncBundleId(value: unknown): value is string {
  if (typeof value !== 'string' || !BUNDLE_ID_PATTERN.test(value)) return false;
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(asBase64(urlSafeToBase64(value)));
  } catch {
    // The decoder refuses a string with nonzero padding bits.
    return false;
  }
  return bytes.length === BUNDLE_ID_BYTES && bytesToUrlSafeBase64(bytes) === value;
}

/** A new bundle ID: 16 random bytes, as base64url with no padding. */
export function newFirstSyncBundleId(): string {
  return bytesToUrlSafeBase64(generateRandomBytesSync(BUNDLE_ID_BYTES));
}

/**
 * Check a received first sync: each rule of the send, a version of 1, a
 * bundle ID of 16 bytes, and a non-negative safe integer creation time.
 *
 * @returns The input without the members that the bundle does not define,
 *   or undefined when a check fails
 */
export function receivedFirstSync(input: unknown): FirstSyncInput | undefined {
  try {
    checkFirstSyncBundle(input);
  } catch {
    return undefined;
  }
  const value = input as FirstSyncInput;
  if (value.version !== 1 || !isFirstSyncBundleId(value.bundleId) || !isNonNegativeSafeInteger(value.createdAt)) {
    return undefined;
  }
  return value;
}

/** The parts of a bundle, with no member that the bundle type does not define. */
export function firstSyncBundleOf(
  input: HostedSignalProtocolRelayFirstSyncBundle,
): HostedSignalProtocolRelayFirstSyncBundle {
  return {
    ...(input.profileKey === undefined ? {} : { profileKey: input.profileKey }),
    ...(input.settings === undefined
      ? {}
      : {
          settings: {
            readReceipts: input.settings.readReceipts,
            typingIndicators: input.settings.typingIndicators,
          },
        }),
    ...(input.contacts === undefined
      ? {}
      : {
          contacts: input.contacts.map((contact) => ({
            userId: contact.userId,
            ...(contact.profileKey === undefined ? {} : { profileKey: contact.profileKey }),
            ...(contact.applicationData === undefined ? {} : { applicationData: contact.applicationData }),
          })),
        }),
    ...(input.blocked === undefined
      ? {}
      : {
          blocked: input.blocked.map((entry) => ({
            recipientId: entry.recipientId,
            blockedAt: entry.blockedAt,
          })),
        }),
    ...(input.applicationData === undefined ? {} : { applicationData: input.applicationData }),
  };
}

/** The apply-once record of a receiving device. */
export interface FirstSyncRecord {
  readonly version: 1;
  /** The newest applied bundle IDs, oldest first. At most 32. */
  readonly bundleIds: readonly string[];
  /** The largest applied creation time. */
  readonly maxCreatedAt: number;
}

function invalidFirstSyncRecord(): Error {
  return new Error('Stored Signal Protocol Relay first-sync state is invalid');
}

/** Read the apply-once record, or null when the store has none. */
export async function readFirstSyncRecord(storage: SignalProtocolLocalStore): Promise<FirstSyncRecord | null> {
  const stored = await storage.getMetadata(FIRST_SYNC_RECORD_METADATA_KEY);
  if (stored === null || stored === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    throw invalidFirstSyncRecord();
  }
  if (
    !isRecord(parsed) ||
    parsed.version !== 1 ||
    !Array.isArray(parsed.bundleIds) ||
    parsed.bundleIds.length > APPLIED_BUNDLE_IDS_MAXIMUM ||
    !parsed.bundleIds.every(isFirstSyncBundleId) ||
    !isNonNegativeSafeInteger(parsed.maxCreatedAt)
  ) {
    throw invalidFirstSyncRecord();
  }
  return { version: 1, bundleIds: [...(parsed.bundleIds as string[])], maxCreatedAt: parsed.maxCreatedAt };
}

/** How a receiving device treats a received bundle, by its apply-once record. */
export function firstSyncDecision(
  record: FirstSyncRecord | null,
  input: Pick<FirstSyncInput, 'bundleId' | 'createdAt'>,
): 'apply' | 'repeat' | 'stale' {
  if (record === null) return 'apply';
  if (record.bundleIds.includes(input.bundleId)) return 'repeat';
  return input.createdAt < record.maxCreatedAt ? 'stale' : 'apply';
}

/** Write the apply-once record after an applied bundle. */
export async function writeAppliedFirstSync(
  storage: SignalProtocolLocalStore,
  record: FirstSyncRecord | null,
  input: Pick<FirstSyncInput, 'bundleId' | 'createdAt'>,
): Promise<void> {
  const bundleIds = [...(record?.bundleIds ?? []).filter((bundleId) => bundleId !== input.bundleId), input.bundleId];
  const next: FirstSyncRecord = {
    version: 1,
    bundleIds: bundleIds.slice(-APPLIED_BUNDLE_IDS_MAXIMUM),
    maxCreatedAt: Math.max(record?.maxCreatedAt ?? 0, input.createdAt),
  };
  await storage.setMetadata(FIRST_SYNC_RECORD_METADATA_KEY, JSON.stringify(next));
}

/**
 * Consume a received first sync on this device (wire contract section 11.4,
 * rules 20 to 27). The caller holds the first-sync lock, so two deliveries
 * do not both apply one bundle.
 *
 * - A sender other than device 1 gives `FIRST_SYNC_NOT_FROM_PRIMARY`.
 * - Content that fails a check gives `FIRST_SYNC_MALFORMED`.
 * - A repeat of an applied bundle ID gives nothing.
 * - A `createdAt` below the largest applied one gives `FIRST_SYNC_STALE`.
 * - No receiver gives `FIRST_SYNC_UNHANDLED`.
 * - Else the receiver runs, and the record is written after it resolves.
 *
 * Each case writes no record, except the last one.
 *
 * @param call - Calls the receiver. The caller can run it as app code.
 * @throws the error of the receiver, with no record written
 */
export async function consumeFirstSync(options: {
  readonly storage: SignalProtocolLocalStore;
  readonly logger: Required<Logger>;
  readonly receiver: HostedSignalProtocolRelayFirstSyncCallback | undefined;
  /** The `firstSync` member of the parsed sync content. */
  readonly input: unknown;
  readonly senderDeviceId: number;
  readonly call?: (receive: () => void | Promise<void>) => Promise<void>;
}): Promise<void> {
  const { storage, logger, receiver, senderDeviceId } = options;
  const warn = (message: string, behavior: string) =>
    logger.warn(message, { category: 'E2EE', data: { behavior, senderDeviceId } });
  if (senderDeviceId !== FIRST_SYNC_SENDER_DEVICE_ID) {
    warn('A first sync came from an own device other than device 1', 'FIRST_SYNC_NOT_FROM_PRIMARY');
    return;
  }
  const input = receivedFirstSync(options.input);
  if (input === undefined) {
    warn('A first sync carried a malformed bundle', 'FIRST_SYNC_MALFORMED');
    return;
  }
  const record = await readFirstSyncRecord(storage);
  const decision = firstSyncDecision(record, input);
  if (decision === 'repeat') return;
  if (decision === 'stale') {
    warn('A first sync was older than an applied first sync', 'FIRST_SYNC_STALE');
    return;
  }
  if (receiver === undefined) {
    warn('A first sync arrived with no onFirstSync callback', 'FIRST_SYNC_UNHANDLED');
    return;
  }
  const details = { bundleId: input.bundleId, senderDeviceId, createdAt: new Date(input.createdAt) };
  const receive = () => receiver(firstSyncBundleOf(input), details);
  await (options.call === undefined ? receive() : options.call(receive));
  await writeAppliedFirstSync(storage, record, input);
}
