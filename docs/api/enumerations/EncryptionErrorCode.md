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

Counter has reached MAX_SAFE_INTEGER - session must be rotated.
This is a safety check to prevent cryptographic issues from counter wrap-around.

***

### DATABASE\_ERROR

> **DATABASE\_ERROR**: `"DATABASE_ERROR"`

Database operation failed

***

### DATABASE\_LOCKED

> **DATABASE\_LOCKED**: `"DATABASE_LOCKED"`

Database is locked or unavailable.

Encrypted database cannot be accessed (wrong password, corruption, etc.)

***

### DECRYPTION\_FAILED

> **DECRYPTION\_FAILED**: `"DECRYPTION_FAILED"`

Message decryption failed

***

### ENCRYPTION\_FAILED

> **ENCRYPTION\_FAILED**: `"ENCRYPTION_FAILED"`

Message encryption failed

***

### HMAC\_VERIFICATION\_FAILED

> **HMAC\_VERIFICATION\_FAILED**: `"HMAC_VERIFICATION_FAILED"`

HMAC verification failed (message tampering detected)

***

### IDENTITY\_KEY\_CHANGED

> **IDENTITY\_KEY\_CHANGED**: `"IDENTITY_KEY_CHANGED"`

Identity key changed (possible MITM attack).

Remote party's identity key differs from previously saved value.
Could be legitimate (reinstall) or an attack.

***

### IDENTITY\_KEY\_ERROR

> **IDENTITY\_KEY\_ERROR**: `"IDENTITY_KEY_ERROR"`

Identity key pair generation or loading failed

***

### IDENTITY\_MISMATCH

> **IDENTITY\_MISMATCH**: `"IDENTITY_MISMATCH"`

Sender identity mismatch.

The sender address in the message doesn't match the expected address.
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

DH public key is malformed or fails validation.

***

### INVALID\_MESSAGE\_VERSION

> **INVALID\_MESSAGE\_VERSION**: `"INVALID_MESSAGE_VERSION"`

Invalid message version or protocol mismatch.

Message was encrypted with an incompatible protocol version.

***

### INVALID\_PREKEY\_BUNDLE

> **INVALID\_PREKEY\_BUNDLE**: `"INVALID_PREKEY_BUNDLE"`

PreKey bundle is invalid or malformed

***

### INVALID\_REGISTRATION\_ID

> **INVALID\_REGISTRATION\_ID**: `"INVALID_REGISTRATION_ID"`

Invalid registration ID.

Registration ID is 0 or doesn't match expected format.

***

### INVALID\_STATE

> **INVALID\_STATE**: `"INVALID_STATE"`

Invalid operation or state

***

### KDF\_ERROR

> **KDF\_ERROR**: `"KDF_ERROR"`

Key derivation function failed

***

### KEY\_STORAGE\_ERROR

> **KEY\_STORAGE\_ERROR**: `"KEY_STORAGE_ERROR"`

Key storage operation failed

***

### KYBER\_ERROR

> **KYBER\_ERROR**: `"KYBER_ERROR"`

Post-quantum (Kyber) operation failed

***

### MESSAGE\_DUPLICATE

> **MESSAGE\_DUPLICATE**: `"MESSAGE_DUPLICATE"`

Duplicate message detected (replay attack).

Message number has already been processed.

***

### MESSAGE\_TOO\_OLD

> **MESSAGE\_TOO\_OLD**: `"MESSAGE_TOO_OLD"`

Message arrived too old to decrypt.

Message keys have been deleted due to age or count limits.

***

### PQXDH\_FAILED

> **PQXDH\_FAILED**: `"PQXDH_FAILED"`

PQXDH key exchange failed during handshake.

The post-quantum key exchange encountered an error. The session is aborted
rather than downgraded to classical X3DH.

***

### PQXDH\_REQUIRED

> **PQXDH\_REQUIRED**: `"PQXDH_REQUIRED"`

PQXDH (post-quantum key exchange) is required but partner lacks Kyber keys.

Thrown when partner doesn't support the required PQXDH handshake.
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

Signed prekeys or Kyber prekeys have exceeded the maximum allowed age
(14 days by default). Message sending is blocked until rotation succeeds
to maintain forward-secrecy guarantees.

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

***

### RATCHET\_ERROR

> **RATCHET\_ERROR**: `"RATCHET_ERROR"`

DH ratchet error.

Diffie-Hellman key exchange failed or produced invalid output.

***

### RECIPIENT\_NOT\_REGISTERED

> **RECIPIENT\_NOT\_REGISTERED**: `"RECIPIENT_NOT_REGISTERED"`

Recipient has not registered encryption keys.

The target user has no prekey bundle available on the server.
They may not have completed encryption setup.

***

### REGISTRATION\_ID\_CHANGED

> **REGISTRATION\_ID\_CHANGED**: `"REGISTRATION_ID_CHANGED"`

Registration ID changed (session reset detected).

Remote party's registration ID changed, indicating app reinstall.
Old sessions should be archived.

***

### REPLAY\_DETECTED

> **REPLAY\_DETECTED**: `"REPLAY_DETECTED"`

Replay attack detected: envelope.timestamp doesn't match dataMessage.timestamp.

After decryption, the envelope timestamp must match the timestamp inside the encrypted
content. A mismatch indicates an attacker may have re-sent old encrypted content
with manipulated envelope metadata.

***

### SEALED\_SENDER\_AUTH\_FAILED

> **SEALED\_SENDER\_AUTH\_FAILED**: `"SEALED_SENDER_AUTH_FAILED"`

Sealed sender authentication failed.

The unidentified access key was rejected by the server. This may trigger
fallback to identified sender delivery.

***

### SENDER\_KEY\_EXPIRED

> **SENDER\_KEY\_EXPIRED**: `"SENDER_KEY_EXPIRED"`

Sender key has expired based on time-based rotation policy.

The default policy rotates sender keys every two weeks.
The caller should auto-rotate the sender key and redistribute to group members.

***

### SESSION\_CONFLICT

> **SESSION\_CONFLICT**: `"SESSION_CONFLICT"`

Multiple active sessions detected (race condition).

Occurs when both parties try to establish sessions simultaneously.
Requires session archiving and convergence.

***

### SESSION\_CORRUPTED

> **SESSION\_CORRUPTED**: `"SESSION_CORRUPTED"`

Session data is corrupted or invalid

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

Counter has reached maximum value - epoch must be rotated.

***

### SPQR\_EPOCH\_OUT\_OF\_RANGE

> **SPQR\_EPOCH\_OUT\_OF\_RANGE**: `"SPQR_EPOCH_OUT_OF_RANGE"`

SPQR epoch is out of valid range.

Either requesting a future epoch (not yet established) or
an epoch too old (chains already cleaned up).

***

### SPQR\_EPOCH\_REGRESSION

> **SPQR\_EPOCH\_REGRESSION**: `"SPQR_EPOCH_REGRESSION"`

SPQR epoch regression detected.

Received message claims an epoch earlier than current - possible replay.

Reserved: Reserved for future use. Currently epoch regression is handled
via SPQR_EPOCH_OUT_OF_RANGE with oldestEpoch context.

***

### SPQR\_INVALID\_CIPHERTEXT

> **SPQR\_INVALID\_CIPHERTEXT**: `"SPQR_INVALID_CIPHERTEXT"`

Invalid Kyber ciphertext in SPQR context.

Ciphertext has wrong size or format for ML-KEM-1024.

***

### SPQR\_KEY\_ALREADY\_USED

> **SPQR\_KEY\_ALREADY\_USED**: `"SPQR_KEY_ALREADY_USED"`

Attempted to use a message key that was already consumed.

Indicates replay attack or duplicate message.

Reserved: Reserved for future use when replay detection is implemented.

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

### TOO\_MANY\_SKIPPED\_MESSAGES

> **TOO\_MANY\_SKIPPED\_MESSAGES**: `"TOO_MANY_SKIPPED_MESSAGES"`

Too many messages skipped (DoS protection).

Prevents attackers from forcing storage of excessive message keys.
Signal Protocol Section 8.4 recommends limiting skipped messages.

***

### TRIPLE\_RATCHET\_REQUIRED

> **TRIPLE\_RATCHET\_REQUIRED**: `"TRIPLE_RATCHET_REQUIRED"`

Triple Ratchet is required but PQXDH was not used.

Triple Ratchet requires post-quantum material from PQXDH.
Cannot enable Triple Ratchet with classical X3DH handshake.

***

### UNKNOWN\_ERROR

> **UNKNOWN\_ERROR**: `"UNKNOWN_ERROR"`

Unknown or unexpected error

***

### UNTRUSTED\_IDENTITY

> **UNTRUSTED\_IDENTITY**: `"UNTRUSTED_IDENTITY"`

Identity key is not trusted.

User has not verified the identity or it has changed without confirmation.
