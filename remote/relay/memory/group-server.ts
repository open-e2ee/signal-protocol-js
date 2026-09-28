/**
 * Executable §8 group-server reference for the in-memory relay.
 *
 * This wrapper uses the same encrypted-state enforcing engine as production
 * adapters while retaining isolated in-memory storage for conformance tests
 * and local development.
 */

import { generateRandomBytesSync } from '../../../internal/crypto/random';
import type { ServerSecretParams } from '../../../internal/protocol/zk/groups/server-params';
import {
  GroupAuthorizationServerEngine,
  type GroupServerEngineRuntime,
} from '../../../internal/groups/server-engine';

const inMemoryRuntime: GroupServerEngineRuntime = {
  now: () => Date.now(),
  randomBytes: generateRandomBytesSync,
};

export class InMemoryGroupAuthorizationServer extends GroupAuthorizationServerEngine {
  constructor(
    serverSecretParams: ServerSecretParams,
    runtime: GroupServerEngineRuntime = inMemoryRuntime
  ) {
    super(serverSecretParams, runtime);
  }
}
