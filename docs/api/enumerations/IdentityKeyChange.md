[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IdentityKeyChange

# Enumeration: IdentityKeyChange

Result of identity key verification indicating whether the key changed.

Used to detect possible man-in-the-middle (MITM) attacks when identity
keys change unexpectedly.

From Signal Protocol:
"Identity keys should rarely change. A change could indicate device
reinstallation or an active attack."

## Example

```typescript
const change = await saveContactIdentity(address, newIdentityKey);

if (change === IdentityKeyChange.REPLACED_EXISTING) {
  // SECURITY ALERT!
  // This could be legitimate (device reinstall) or an attack
  logger.error('Identity key changed!', {
    address,
    oldKey: await getContactIdentity(address),
    newKey: newIdentityKey
  });

  // Show UI warning to user
  await showSecurityAlert({
    title: 'Security Alert',
    message: `${address.userId}'s security code has changed. ` +
             'This could mean they reinstalled the app, or ' +
             'someone is trying to intercept your messages.',
    actions: ['Verify Safety Number', 'Accept', 'Cancel']
  });
}
```

## Enumeration Members

### CHANGED

> **CHANGED**: `"changed"`

***

### NEW\_IDENTITY

> **NEW\_IDENTITY**: `"new_identity"`

***

### ROLLBACK

> **ROLLBACK**: `"rollback"`

***

### UNCHANGED

> **UNCHANGED**: `"unchanged"`
