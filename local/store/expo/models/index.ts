/**
 * Signal Protocol Models
 *
 * Exports the query, factory, and domain-model operations used by the Expo
 * storage adapter.
 */

// ============================================================================
// Session model
// ============================================================================
export {};
export {
  Session,
  // Query functions
  getSessionById,
  getSessionsByIds,
  getSessionIdsByUserId,
  getAllSessionIds,
  sessionExists,
  countSessions,
  deleteSessionById,
  deleteAllSessions,
  // Factory functions
  createSession,
  createSessionFromRecord,
  deserializeSessionRecord,
  serializeSessionRecord,
} from './session';

// ============================================================================
// Local Identity Model
// ============================================================================
export {
  LocalIdentity,
  getPrimaryIdentityKey,
  primaryIdentityKeyExists,
  countLocalIdentityKeys,
  deletePrimaryIdentityKey,
  deleteAllLocalIdentityKeys,
  getLocalRegistrationId,
  setLocalRegistrationId,
  createPrimaryIdentityKey,
} from './local-identity';

// ============================================================================
// Recipient Identity Model
// ============================================================================
export { buildContactIdentityId } from './identity-key-id';

export {
  RecipientIdentity,
  getContactIdentity,
  getAllContactIdentities,
  countRecipientIdentities,
  deleteContactIdentity,
  deleteAllContactIdentities,
  saveContactIdentity,
  createContactIdentity,
} from './recipient-identity';

// ============================================================================
// EC Signed Prekey Model
// ============================================================================
export {
  EcSignedPreKey,
  // Query functions
  getEcSignedPreKeyByKeyId,
  getCurrentEcSignedPreKey,
  getAllEcSignedPreKeys,
  countEcSignedPreKeys,
  deleteEcSignedPreKeyByKeyId,
  deleteAllEcSignedPreKeys,
  getMaxEcSignedPreKeyId,
  deleteExpiredEcSignedPreKeys,
  storeReplacingEcSignedPreKey,
  cullReplacedEcSignedPreKeys,
  // Factory functions
  createEcSignedPreKey,
} from './ec-signed-prekey';

// ============================================================================
// EC One-Time Prekey Model
// ============================================================================
export {
  EcOneTimePreKey,
  // Query functions
  getEcOneTimePreKeyByKeyId,
  getAllEcOneTimePreKeys,
  countEcOneTimePreKeys,
  deleteEcOneTimePreKeyByKeyId,
  deleteEcOneTimePreKeysByKeyIds,
  deleteAllEcOneTimePreKeys,
  storeBatchEcOneTimePreKeys,
  markAllEcOneTimePreKeysReplaced,
  cullReplacedEcOneTimePreKeys,
  // Factory functions
  createEcOneTimePreKey,
} from './ec-one-time-prekey';

// ============================================================================
// Kyber Prekey Model
// ============================================================================
export {
  KyberPreKey,
  // Query functions
  getKyberPreKeyByKeyId,
  getCurrentKyberPreKey,
  getAllKyberPreKeys,
  countKyberPreKeys,
  deleteKyberPreKeyByKeyId,
  deleteAllKyberPreKeys,
  getMaxKyberPreKeyId,
  cullReplacedKyberPreKeys,
  // Factory functions
  createKyberPreKey,
} from './kyber-prekey';

// ============================================================================
// Kyber One-Time Prekey Model
// ============================================================================
export {
  KyberOneTimePreKey,
  // Query functions
  getKyberOneTimePreKeyByKeyId,
  getAllKyberOneTimePreKeys,
  countKyberOneTimePreKeys,
  deleteKyberOneTimePreKeyByKeyId,
  deleteKyberOneTimePreKeysByKeyIds,
  deleteAllKyberOneTimePreKeys,
  storeBatchKyberOneTimePreKeys,
  markAllKyberOneTimePreKeysReplaced,
  cullReplacedKyberOneTimePreKeys,
  // Factory functions
  createKyberOneTimePreKey,
} from './kyber-one-time-prekey';

// ============================================================================
// Kyber Prekey Used Model (PQXDH replay detection)
// ============================================================================
export {
  ReusedBaseKeyError,
  markKyberPreKeyUsed,
  deleteAllKyberPreKeyUsed,
} from './kyber-prekey-used';

// ============================================================================
// Sender Key Model
// ============================================================================
export {
  SenderKey,
  type StoredSenderKey,
  parseSenderKeyRecord,
  // Query functions
  getSenderKey,
  findGroupBySenderKeyId,
  getSenderKeysByGroup,
  getSenderKeysBySender,
  countSenderKeys,
  countSenderKeysByGroup,
  deleteSenderKey,
  deleteSenderKeysByGroup,
  deleteSenderKeysBySender,
  deleteAllSenderKeys,
  // Factory functions
  createSenderKey,
} from './sender-key';

// ============================================================================
// Message Record Model
// Retry records are indexed by the client timestamp assigned before encryption.
// ============================================================================
export {
  MessageRecord,
  type StoredMessageRecord,
  // Query functions (timestamp-based)
  getMessageRecord,
  deleteMessageRecord,
  // Common query functions
  countMessageRecords,
  deleteExpiredMessageRecords,
  deleteAllMessageRecords,
  deleteMessageRecordsBySessionId,
  // Factory functions
  createMessageRecord,
} from './message-record';

// ============================================================================
// Database Access (for complex queries not covered by models)
// ============================================================================
export { getRawDatabase } from '../db';
