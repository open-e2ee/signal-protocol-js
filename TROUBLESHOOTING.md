# Troubleshooting Guide

> **Navigation**: [README](./README.md) | [ARCHITECTURE](./ARCHITECTURE.md) | **TROUBLESHOOTING**

Guide for debugging OpenE2EE Signal Protocol SDK encryption issues.

---

## Decision Tree

```
Error occurred?
     │
     ├─► "Identity key not found"
     │        └─► Did you use SignalProtocolClient.create()? (not constructor)
     │             └─► See: Initialization Errors
     │
     ├─► "Failed to establish session"
     │        └─► Is prekey bundle valid? (identityKey, signedPreKey required)
     │             └─► See: Session Establishment
     │
     ├─► "No session with address"
     │        └─► Is sessionId in "userId:deviceId" format?
     │             └─► Example: 'bob:1' not just 'bob'
     │
     ├─► "Failed to decrypt"
     │        ├─► Message out of order? → MKSKIPPED handles up to 1000 skipped
     │        ├─► Message too old? → Keys expire after 7 days
     │        └─► Wrong session? → Check sender address parsing
     │
     ├─► "MAC verification failed"
     │        └─► Data corrupted in transit? Check network/storage
     │
     ├─► "PreKeyBundle invalid"
     │        ├─► Signature verification failed → Recipient may have rotated keys
     │        └─► Missing fields → Fetch fresh bundle from server
     │
     └─► Performance issues?
              ├─► Initial load slow? → Key generation is one-time
              ├─► Encryption slow? → Kyber ops ~50ms (normal)
              └─► Memory issues? → Check MKSKIPPED cleanup
```

---

## Common Errors

### Initialization Errors

**"Identity key not found - client not initialized"**

<!-- doc-snippet:illustrative elided-call-arguments -->
```typescript
// ❌ Wrong: forgot to initialize
const signal = new SignalProtocolClient(); // Don't use constructor directly!
await signal.encryptMessage(...); // Error!

// ✅ Correct: use factory method
const signal = await SignalProtocolClient.create(userId, { storage });
await signal.encryptMessage(...); // Works!
```

### Session Establishment

**"Failed to establish session"**

Make sure the prekey bundle is fresh and valid:

<!-- doc-snippet:skip requires-external-context -->
```typescript
// Fetch the latest prekey bundle from server
const bundle = await convex.mutation(api.signal.keys.fetchPreKeyBundle, {
  userId: bobId,
  deviceId: 1,
  identityType: 'aci',
});

// Verify bundle has required fields
if (!bundle.identityKey || !bundle.signedPreKey) {
  throw new Error('Invalid prekey bundle');
}

await signal.establishSession(sessionId, bobId, bundle);
```

### Session ID Format

**"No session with address"**

Session IDs must be in `userId:deviceId` format:

<!-- doc-snippet:skip requires-external-context -->
```typescript
// ❌ Wrong: missing device ID
await signal.encryptMessage('bob', 'Hello');

// ✅ Correct: include device ID
await signal.encryptMessage('bob:1', 'Hello'); // Primary device
await signal.encryptMessage('bob:2', 'Hello'); // Secondary device
```

### Out-of-Order Messages

The protocol handles out-of-order messages automatically via MKSKIPPED. For failures:

1. Check that both parties established sessions
2. Verify message counters are not too far apart (maxSkip limit: 1000)
3. Check that no sender or transport duplicates messages
4. Check that skipped keys did not expire (7-day default)

### Decryption Failures

**"Failed to decrypt" or "MAC verification failed"**

| Symptom     | Cause                   | Solution                                         |
| ----------- | ----------------------- | ------------------------------------------------ |
| MAC failed  | Data corrupted          | Check network, verify no modification in transit |
| Wrong key   | Session mismatch        | Verify sessionId matches sender                  |
| Key expired | Message > 7 days old    | Cannot recover; re-send message                  |
| Counter gap | > 1000 messages skipped | Increase `maxSkip` or re-establish session       |

---

## Debugging Tools

### Check Client State

<!-- doc-snippet:skip requires-external-context -->
```typescript
// Get encryption statistics
const stats = await signal.getStats();
console.log('Has identity key:', stats.hasIdentityKey);
console.log('Session count:', stats.sessionCount);
console.log('OneTime prekeys remaining:', stats.oneTimePreKeysCount);
```

### Check Session Status

<!-- doc-snippet:skip requires-external-context -->
```typescript
// Check if session exists
const hasSession = await signal.hasSession('bob:1');
console.log('Has session with bob:1:', hasSession);
```

### Enable Debug Logging

<!-- doc-snippet:skip requires-external-context -->
```typescript
const signal = await SignalProtocolClient.create(userId, {
  enableDebugLogging: true,
});
// Now all crypto operations will log to console
```

### Verify Identity Keys

<!-- doc-snippet:skip requires-external-context -->
```typescript
// Generate the composite safety number from the locally pinned identity.
const safetyNumber = await signal.verify(theirUserId);
console.log('Safety number:', safetyNumber.numeric);
// Compare this with the other party via video call, in person, etc.
await signal.confirmSafetyNumber(safetyNumber.confirmation);
```

---

## Layer-Specific Debugging

| Issue                     | Layer               |
| ------------------------- | ------------------- |
| Key generation            | `internal/crypto/`  |
| Key types, bundles        | `keys/`             |
| Key exchange (X3DH/PQXDH) | `internal/protocol/` |
| Ratchet state             | `internal/protocol/` |
| Session state             | `internal/session/` |
| Multi-device              | `internal/sesame/`  |

---

## Related Guides

- **[docs/ERROR_HANDLING.md](./docs/ERROR_HANDLING.md)** - Error classes, codes, and recovery patterns
- **[SECURITY.md](./SECURITY.md)** - Security-related debugging

---

## Performance Issues

### Expected Timings

| Operation                   | Expected Time | Notes                 |
| --------------------------- | ------------- | --------------------- |
| Key generation (first time) | 500-1000ms    | One-time cost         |
| Session establishment       | 100-200ms     | Includes Kyber ops    |
| Message encrypt             | 5-20ms        | Per message           |
| Message decrypt             | 5-20ms        | Per message           |
| Kyber encapsulate           | ~50ms         | Post-quantum overhead |

### Memory Considerations

- **MKSKIPPED keys**: Up to 1000 stored per session (DoS protection)
- **Key expiration**: Automatic cleanup after 7 days
- **Session cleanup**: Call `deleteSession()` for inactive contacts

---

**Last Updated**: 2025-12-01
**Maintainer**: OpenE2EE Engineering Team
