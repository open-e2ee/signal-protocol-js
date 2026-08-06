/**
 * Executable §8 group-server reference for the in-memory relay.
 *
 * This wrapper uses the same encrypted-state enforcing engine as production
 * adapters while retaining isolated in-memory storage for conformance tests
 * and local development.
 */

export {
  GroupAuthorizationServerEngine as InMemoryGroupAuthorizationServer,
} from '../../../internal/groups/server-engine';
