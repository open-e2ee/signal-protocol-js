/**
 * Backend-conformance kit for application-supplied React Native storage.
 *
 * `ReactNativeSignalProtocolStore` delegates persistence to a
 * `ReactNativeKeyValueStorage` backend the application provides, so the SDK
 * cannot exercise that backend itself. This kit is the executable form of the
 * backend contract. An application runs it against its own backend. A clean
 * result is the precondition for every durability and atomicity promise the
 * store makes on top.
 *
 * The `atomicWrite` cases matter most. The store commits identity trust,
 * session state, and one-time-prekey consumption through `atomicWrite` as one
 * security transition. A backend that reorders, interleaves, or partially
 * applies those batches silently breaks that guarantee.
 *
 * The kit has no framework or platform dependencies, and avoids class syntax.
 * It runs unchanged under jest, Node, a browser, or the Hermes engine that
 * ships with React Native.
 *
 * @example
 * ```typescript
 * import { assertBackendConformance } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';
 *
 * await assertBackendConformance({
 *   createBackend: () => openMyBackend({ namespace: freshNamespace() }),
 *   reopen: (previous) => reopenMyBackend(previous),
 * });
 * ```
 */

import type { ReactNativeKeyValueStorage } from './storage';

export interface BackendConformanceOptions {
  /**
   * Return a backend over fresh, empty storage. Called once per case so
   * cases cannot contaminate each other. A real implementation typically
   * opens a new namespace, file, or database per call.
   */
  createBackend(): ReactNativeKeyValueStorage | Promise<ReactNativeKeyValueStorage>;
  /**
   * Reopen the given backend's persisted data as a fresh handle, the way a
   * process restart would. Optional: without it the durability case is
   * reported in `skipped` instead of running.
   */
  reopen?(
    previous: ReactNativeKeyValueStorage
  ): ReactNativeKeyValueStorage | Promise<ReactNativeKeyValueStorage>;
}

export interface BackendConformanceFailure {
  name: string;
  message: string;
}

export interface BackendConformanceResult {
  /** Number of cases in the kit, including skipped ones. */
  total: number;
  passed: string[];
  /** Cases that could not run with the supplied options, never silent. */
  skipped: string[];
  failures: BackendConformanceFailure[];
}

/**
 * The session key prefix the store uses, so `removeSessionsForUser` cases
 * exercise the exact keyspace shape a backend will see in production.
 */
const SESSION_PREFIX = '@signal:sessions:';

/**
 * Session values under the prefix are JSON envelopes whose plaintext routing
 * metadata carries the exact userId. `removeSessionsForUser` must match on
 * that field, never on the key. The `data` field is opaque to the backend.
 */
function sessionEnvelope(userId: string, deviceId: number): string {
  return JSON.stringify({
    userId: userId,
    deviceId: deviceId,
    data: 'b3BhcXVlLWNpcGhlcnRleHQ=',
    updatedAt: 1,
  });
}

function fail(message: string): never {
  throw new Error(message);
}

function assertEqual(actual: unknown, expected: unknown, context: string): void {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    fail(context + ': expected ' + expectedJson + ', got ' + actualJson);
  }
}

async function expectRejection(promise: Promise<unknown>, context: string): Promise<unknown> {
  let error: unknown = null;
  let rejected = false;
  await promise.then(
    function resolved() {},
    function caught(reason: unknown) {
      rejected = true;
      error = reason;
    }
  );
  if (!rejected) fail(context + ': expected the call to reject, but it resolved');
  return error;
}

interface ConformanceCase {
  name: string;
  needsReopen?: boolean;
  run(backend: ReactNativeKeyValueStorage, options: BackendConformanceOptions): Promise<void>;
}

const CASES: ConformanceCase[] = [
  {
    name: 'getItem returns null for a missing key',
    async run(backend) {
      assertEqual(await backend.getItem('missing'), null, 'missing key');
    },
  },
  {
    name: 'setItem stores, overwrites, and round-trips values',
    async run(backend) {
      await backend.setItem('plain', 'value-1');
      assertEqual(await backend.getItem('plain'), 'value-1', 'first write');
      await backend.setItem('plain', 'value-2');
      assertEqual(await backend.getItem('plain'), 'value-2', 'overwrite');

      const unicode = 'café 日本語 🔐 \u0000null-byte';
      await backend.setItem('unicode', unicode);
      assertEqual(await backend.getItem('unicode'), unicode, 'unicode round-trip');

      let long = '';
      while (long.length < 8192) long += 'abcdefghijklmnop';
      await backend.setItem('long', long);
      assertEqual(await backend.getItem('long'), long, 'long value round-trip');
    },
  },
  {
    name: 'removeItem deletes and tolerates a missing key',
    async run(backend) {
      await backend.setItem('doomed', 'value');
      await backend.removeItem('doomed');
      assertEqual(await backend.getItem('doomed'), null, 'after removeItem');
      await backend.removeItem('doomed');
      assertEqual(await backend.getItem('doomed'), null, 'removeItem is idempotent');
    },
  },
  {
    name: 'getAllKeys lists exactly the stored keys',
    async run(backend) {
      assertEqual(await backend.getAllKeys(), [], 'empty backend');
      await backend.setItem('b', '2');
      await backend.setItem('a', '1');
      await backend.setItem('c', '3');
      await backend.removeItem('c');
      const keys = (await backend.getAllKeys()).slice().sort();
      assertEqual(keys, ['a', 'b'], 'stored keys');
    },
  },
  {
    name: 'removeMany removes listed keys and tolerates missing ones',
    async run(backend) {
      await backend.setItem('one', '1');
      await backend.setItem('two', '2');
      await backend.setItem('three', '3');
      await backend.removeMany(['one', 'three', 'never-existed']);
      assertEqual(await backend.getItem('one'), null, 'first removed key');
      assertEqual(await backend.getItem('three'), null, 'second removed key');
      assertEqual(await backend.getItem('two'), '2', 'unlisted key survives');
    },
  },
  {
    name: 'atomicWrite applies operations in order',
    async run(backend) {
      await backend.atomicWrite([
        { type: 'set', key: 'ordered', value: 'first' },
        { type: 'set', key: 'ordered', value: 'second' },
      ]);
      assertEqual(await backend.getItem('ordered'), 'second', 'later set wins');

      await backend.atomicWrite([
        { type: 'set', key: 'transient', value: 'created' },
        { type: 'remove', key: 'transient' },
      ]);
      assertEqual(await backend.getItem('transient'), null, 'set then remove');

      await backend.atomicWrite([
        { type: 'remove', key: 'reborn' },
        { type: 'set', key: 'reborn', value: 'alive' },
      ]);
      assertEqual(await backend.getItem('reborn'), 'alive', 'remove then set');
    },
  },
  {
    name: 'atomicWrite evaluates checks against pre-batch state',
    async run(backend) {
      await backend.setItem('guarded', 'old');
      // The check follows a set of the same key in batch order. The contract
      // evaluates every check before any write, so it must see 'old'.
      await backend.atomicWrite([
        { type: 'set', key: 'guarded', value: 'new' },
        { type: 'check', key: 'guarded', expectedValue: 'old' },
      ]);
      assertEqual(await backend.getItem('guarded'), 'new', 'batch committed');
    },
  },
  {
    name: 'atomicWrite guards creation with an expectedValue of null',
    async run(backend) {
      await backend.atomicWrite([
        { type: 'check', key: 'created', expectedValue: null },
        { type: 'set', key: 'created', value: 'first-writer' },
      ]);
      assertEqual(await backend.getItem('created'), 'first-writer', 'first creation');

      await expectRejection(
        backend.atomicWrite([
          { type: 'check', key: 'created', expectedValue: null },
          { type: 'set', key: 'created', value: 'second-writer' },
        ]),
        'creation of an existing key'
      );
      assertEqual(await backend.getItem('created'), 'first-writer', 'loser wrote nothing');
    },
  },
  {
    name: 'a failed check applies none of the batch',
    async run(backend) {
      await backend.setItem('anchor', 'anchored');
      await expectRejection(
        backend.atomicWrite([
          { type: 'set', key: 'before-check', value: 'must-not-appear' },
          { type: 'check', key: 'anchor', expectedValue: 'something-else' },
          { type: 'set', key: 'after-check', value: 'must-not-appear' },
        ]),
        'batch with a failing check'
      );
      assertEqual(await backend.getItem('before-check'), null, 'write before the check');
      assertEqual(await backend.getItem('after-check'), null, 'write after the check');
      assertEqual(await backend.getItem('anchor'), 'anchored', 'checked key');
    },
  },
  {
    name: 'removeSessionsForUser removes only exact userId matches under the prefix',
    async run(backend) {
      await backend.setItem(SESSION_PREFIX + 'alice:1', sessionEnvelope('alice', 1));
      await backend.setItem(SESSION_PREFIX + 'alice:2', sessionEnvelope('alice', 2));
      // 'alice2' starts with 'alice'. A substring or startsWith match on the
      // userId would delete an unrelated user's session.
      await backend.setItem(SESSION_PREFIX + 'alice2:1', sessionEnvelope('alice2', 1));
      await backend.setItem(SESSION_PREFIX + 'bob:1', sessionEnvelope('bob', 1));
      await backend.setItem('@signal:contacts:alice', sessionEnvelope('alice', 1));

      await backend.atomicWrite([
        { type: 'removeSessionsForUser', keyPrefix: SESSION_PREFIX, userId: 'alice' },
      ]);

      assertEqual(await backend.getItem(SESSION_PREFIX + 'alice:1'), null, 'alice device 1');
      assertEqual(await backend.getItem(SESSION_PREFIX + 'alice:2'), null, 'alice device 2');
      assertEqual(
        await backend.getItem(SESSION_PREFIX + 'alice2:1'),
        sessionEnvelope('alice2', 1),
        'a userId that begins with the target'
      );
      assertEqual(
        await backend.getItem(SESSION_PREFIX + 'bob:1'),
        sessionEnvelope('bob', 1),
        'an unrelated userId'
      );
      assertEqual(
        await backend.getItem('@signal:contacts:alice'),
        sessionEnvelope('alice', 1),
        'a matching value outside the prefix'
      );
    },
  },
  {
    name: 'removeSessionsForUser observes writes earlier in its batch',
    async run(backend) {
      // A session created inside the same transaction that rotates identity
      // must be visible to the removal, or it survives trusted under the
      // rotated identity. Enumeration snapshotted before the batch applies
      // is the defect this case exists to catch.
      await backend.atomicWrite([
        { type: 'set', key: SESSION_PREFIX + 'carol:1', value: sessionEnvelope('carol', 1) },
        { type: 'removeSessionsForUser', keyPrefix: SESSION_PREFIX, userId: 'carol' },
      ]);
      assertEqual(
        await backend.getItem(SESSION_PREFIX + 'carol:1'),
        null,
        'session written earlier in the batch'
      );
    },
  },
  {
    name: 'concurrent guarded batches have exactly one winner',
    async run(backend) {
      function attempt(value: string): Promise<string | null> {
        return backend
          .atomicWrite([
            { type: 'check', key: 'contested', expectedValue: null },
            { type: 'set', key: 'contested', value: value },
          ])
          .then(
            function won(): string {
              return value;
            },
            function lost(): null {
              return null;
            }
          );
      }
      const outcomes = await Promise.all([attempt('left'), attempt('right')]);
      const winners: string[] = [];
      for (const outcome of outcomes) {
        if (outcome !== null) winners.push(outcome);
      }
      if (winners.length !== 1) {
        fail(
          'expected exactly one of two concurrent guarded batches to commit, got ' +
            winners.length
        );
      }
      assertEqual(await backend.getItem('contested'), winners[0], 'committed value');
    },
  },
  {
    name: 'committed writes survive reopen',
    needsReopen: true,
    async run(backend, options) {
      await backend.setItem('durable-plain', 'kept');
      await backend.atomicWrite([
        { type: 'check', key: 'durable-batch', expectedValue: null },
        { type: 'set', key: 'durable-batch', value: 'also-kept' },
      ]);
      // Deletions must be as durable as writes. A backend that persists sets
      // but resurrects removed keys after reopen would leave sessions alive
      // that the store deleted during an identity rotation.
      await backend.setItem('durable-removed', 'doomed');
      await backend.removeItem('durable-removed');
      await backend.setItem(SESSION_PREFIX + 'carol:9', sessionEnvelope('carol', 9));
      await backend.atomicWrite([
        { type: 'removeSessionsForUser', keyPrefix: SESSION_PREFIX, userId: 'carol' },
      ]);
      const reopened = await options.reopen!(backend);
      assertEqual(await reopened.getItem('durable-plain'), 'kept', 'plain write after reopen');
      assertEqual(
        await reopened.getItem('durable-batch'),
        'also-kept',
        'batched write after reopen'
      );
      assertEqual(
        await reopened.getItem('durable-removed'),
        null,
        'removed key stays absent after reopen'
      );
      assertEqual(
        await reopened.getItem(SESSION_PREFIX + 'carol:9'),
        null,
        'removed session stays absent after reopen'
      );
    },
  },
];

/**
 * Run every conformance case against backends produced by
 * `options.createBackend` and report the outcome without throwing.
 */
export async function runBackendConformance(
  options: BackendConformanceOptions
): Promise<BackendConformanceResult> {
  const result: BackendConformanceResult = {
    total: CASES.length,
    passed: [],
    skipped: [],
    failures: [],
  };
  for (const conformanceCase of CASES) {
    if (conformanceCase.needsReopen && !options.reopen) {
      result.skipped.push(conformanceCase.name);
      continue;
    }
    try {
      const backend = await options.createBackend();
      await conformanceCase.run(backend, options);
      result.passed.push(conformanceCase.name);
    } catch (error) {
      const message =
        error !== null && typeof error === 'object' && 'message' in error
          ? String((error as { message: unknown }).message)
          : String(error);
      result.failures.push({ name: conformanceCase.name, message: message });
    }
  }
  return result;
}

/**
 * Run the kit and throw with every failure listed when the backend does not
 * conform. The intended form for an application's own automated checks.
 */
export async function assertBackendConformance(
  options: BackendConformanceOptions
): Promise<BackendConformanceResult> {
  const result = await runBackendConformance(options);
  if (result.failures.length > 0) {
    const lines: string[] = [];
    for (const failure of result.failures) {
      lines.push('- ' + failure.name + ': ' + failure.message);
    }
    throw new Error(
      'Backend conformance failed (' +
        result.failures.length +
        ' of ' +
        result.total +
        ' cases):\n' +
        lines.join('\n')
    );
  }
  return result;
}
