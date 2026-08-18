[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / EncryptionErrorCode

# Enumeration: EncryptionErrorCode

Stable encryption error codes for programmatic handling.

Organized by category for better error handling and user messaging.
Provides extensive error code set.

## Enumeration Members

### COUNTER\_OVERFLOW

> **COUNTER\_OVERFLOW**: `"COUNTER_OVERFLOW"`

Message counter overflow.

The counter reached MAX_SAFE_INTEGER, so the caller must rotate the session.
This is a safety check to prevent cryptographic issues from counter wrap-around.

***

### DECRYPTION\_FAILED

> **DECRYPTION\_FAILED**: `"DECRYPTION_FAILED"`

Message decryption failed

***

### ENCRYPTION\_FAILED

> **ENCRYPTION\_FAILED**: `"ENCRYPTION_FAILED"`

Message encryption failed

***

### IDENTITY\_MISMATCH

> **IDENTITY\_MISMATCH**: `"IDENTITY_MISMATCH"`

Sender identity mismatch.

The sender address in the message does not match the expected address.
This indicates a session hijacking attempt where an attacker tries to
inject their messages under a different identity.

***

### INITIALIZATION\_FAILED

> **INITIALIZATION\_FAILED**: `"INITIALIZATION_FAILED"`

Signal Protocol initialization failed

***

### INVALID\_CIPHERTEXT

> **INVALID\_CIPHERTEXT**: `"INVALID_CIPHERTEXT"`

Message ciphertext is invalid or malformed

***

### INVALID\_DH\_KEY

> **INVALID\_DH\_KEY**: `"INVALID_DH_KEY"`

Invalid DH public key.

A malformed DH public key, or one that fails validation.

***

### INVALID\_PREKEY\_BUNDLE

> **INVALID\_PREKEY\_BUNDLE**: `"INVALID_PREKEY_BUNDLE"`

PreKey bundle is invalid or malformed

***

### INVALID\_STATE

> **INVALID\_STATE**: `"INVALID_STATE"`

Invalid operation or state

***

### KEY\_STORAGE\_ERROR

> **KEY\_STORAGE\_ERROR**: `"KEY_STORAGE_ERROR"`

Key storage operation failed

***

### MESSAGE\_DUPLICATE

> **MESSAGE\_DUPLICATE**: `"MESSAGE_DUPLICATE"`

Duplicate message detected (replay attack).

The session already processed this message number.

***

### PQXDH\_FAILED

> **PQXDH\_FAILED**: `"PQXDH_FAILED"`

PQXDH key exchange failed during handshake.

The post-quantum key exchange encountered an error. The SDK aborts the
session instead of a downgrade to classical X3DH.

***

### PQXDH\_REQUIRED

> **PQXDH\_REQUIRED**: `"PQXDH_REQUIRED"`

PQXDH (post-quantum key exchange) applies, but the partner lacks Kyber keys.

Thrown when partner does not support the required PQXDH handshake.
Application can catch this to notify user or queue message for retry.

***

### PREKEY\_FETCH\_RATE\_LIMITED

> **PREKEY\_FETCH\_RATE\_LIMITED**: `"PREKEY_FETCH_RATE_LIMITED"`

Rate limited - too many prekey bundle fetches.

Server enforces rate limits to prevent prekey drainage attacks.

***

### PREKEY\_NOT\_FOUND

> **PREKEY\_NOT\_FOUND**: `"PREKEY_NOT_FOUND"`

PreKey not found

***

### PREKEY\_ROTATION\_REQUIRED

> **PREKEY\_ROTATION\_REQUIRED**: `"PREKEY_ROTATION_REQUIRED"`

PreKey rotation required before sending.

Signed prekeys or Kyber prekeys are past the maximum allowed age
(14 days by default). The client blocks message sending until rotation
succeeds, which maintains the forward-secrecy guarantees.

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

***

### RECIPIENT\_NOT\_REGISTERED

> **RECIPIENT\_NOT\_REGISTERED**: `"RECIPIENT_NOT_REGISTERED"`

Recipient has not registered encryption keys.

The target user has no prekey bundle available on the server.
Their encryption setup may be incomplete.

***

### REPLAY\_DETECTED

> **REPLAY\_DETECTED**: `"REPLAY_DETECTED"`

Replay attack detected: envelope.timestamp does not match dataMessage.timestamp.

After decryption, the envelope timestamp must match the timestamp inside the encrypted
content. A mismatch indicates an attacker may have re-sent old encrypted content
with manipulated envelope metadata.

***

### SEALED\_SENDER\_AUTH\_FAILED

> **SEALED\_SENDER\_AUTH\_FAILED**: `"SEALED_SENDER_AUTH_FAILED"`

Sealed sender authentication failed.

The server rejected the unidentified access key. This may trigger
fallback to identified sender delivery.

***

### SENDER\_KEY\_EXPIRED

> **SENDER\_KEY\_EXPIRED**: `"SENDER_KEY_EXPIRED"`

The sender key expired under the time-based rotation policy.

The default policy rotates sender keys every two weeks.
The caller should auto-rotate the sender key and redistribute to group members.

***

### SESSION\_CORRUPTED

> **SESSION\_CORRUPTED**: `"SESSION_CORRUPTED"`

Damaged or invalid session data

***

### SESSION\_ESTABLISHMENT\_FAILED

> **SESSION\_ESTABLISHMENT\_FAILED**: `"SESSION_ESTABLISHMENT_FAILED"`

Session establishment failed after retries.

Could not establish a session with the recipient after
multiple attempts. May indicate network issues.

***

### SESSION\_NOT\_FOUND

> **SESSION\_NOT\_FOUND**: `"SESSION_NOT_FOUND"`

Session not found for the given address

***

### SIGNATURE\_VERIFICATION\_FAILED

> **SIGNATURE\_VERIFICATION\_FAILED**: `"SIGNATURE_VERIFICATION_FAILED"`

Signature verification failed

***

### SPQR\_COUNTER\_OVERFLOW

> **SPQR\_COUNTER\_OVERFLOW**: `"SPQR_COUNTER_OVERFLOW"`

SPQR message counter overflow.

The counter reached its maximum value, so the caller must rotate the epoch.

***

### SPQR\_EPOCH\_OUT\_OF\_RANGE

> **SPQR\_EPOCH\_OUT\_OF\_RANGE**: `"SPQR_EPOCH_OUT_OF_RANGE"`

SPQR epoch is out of valid range.

Either requesting a future epoch (not yet established) or
an epoch too old (chains already cleaned up).

***

### SPQR\_INVALID\_CIPHERTEXT

> **SPQR\_INVALID\_CIPHERTEXT**: `"SPQR_INVALID_CIPHERTEXT"`

Invalid Kyber ciphertext in SPQR context.

Ciphertext has wrong size or format for ML-KEM-1024.

***

### SPQR\_MESSAGE\_JUMP\_TOO\_LARGE

> **SPQR\_MESSAGE\_JUMP\_TOO\_LARGE**: `"SPQR_MESSAGE_JUMP_TOO_LARGE"`

Message number jump too large (DoS protection).

Prevents attackers from forcing storage of excessive skipped keys.
`SPQR`'s the profile uses `max_jump` of 25,000.

***

### SPQR\_VERSION\_MISMATCH

> **SPQR\_VERSION\_MISMATCH**: `"SPQR_VERSION_MISMATCH"`

SPQR version negotiation failed.

Peer's maximum supported version is below our minimum required version.
For example, peer only supports V0 but we require V1.

***

### STORAGE\_QUOTA\_EXCEEDED

> **STORAGE\_QUOTA\_EXCEEDED**: `"STORAGE_QUOTA_EXCEEDED"`

The storage backend rejected a write because the origin ran out of
storage quota.

The rejected write did not persist. Storage adapters commit each
write in an atomic transaction, so quota exhaustion rolls the whole
transaction back instead of leaving a subset. The application should
free space or request more from the platform, then retry.

***

### TOO\_MANY\_SKIPPED\_MESSAGES

> **TOO\_MANY\_SKIPPED\_MESSAGES**: `"TOO_MANY_SKIPPED_MESSAGES"`

Too many messages skipped (DoS protection).

Prevents attackers from forcing storage of excessive message keys.
Signal Protocol Section 8.4 recommends limiting skipped messages.

***

### TRIPLE\_RATCHET\_REQUIRED

> **TRIPLE\_RATCHET\_REQUIRED**: `"TRIPLE_RATCHET_REQUIRED"`

Triple Ratchet applies, but the session did not use PQXDH.

Triple Ratchet requires post-quantum material from PQXDH.
Cannot enable Triple Ratchet with classical X3DH handshake.

***

### UNTRUSTED\_IDENTITY

> **UNTRUSTED\_IDENTITY**: `"UNTRUSTED_IDENTITY"`

Identity key is not trusted.

The user did not verify the identity, or the identity changed without
confirmation.
