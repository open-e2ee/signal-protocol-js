/**
 * Public username API.
 *
 * This is the supported boundary for username hashing, formatting, generation,
 * and zero-knowledge proof helpers. App and server code should import from
 * here instead of reaching into internal protocol files.
 */

export {};
export {
  G1,
  G2,
  G3,
  USERNAME_HASH_LENGTH,
  MAX_NICKNAME_LENGTH,
  hashUsername,
  usernameScalars,
  parseUsername,
  formatUsername,
  generateDiscriminatorCandidates,
  validateNickname,
  validateDiscriminator,
} from '../internal/protocol/username/hash';

export {
  USERNAME_PROOF_LENGTH,
  proveUsernameKnowledge,
  verifyUsernameProof,
} from '../internal/protocol/username/proof';

export { generateNickname } from '../internal/protocol/username/generate';
