[**@open-e2ee/signal-protocol-sdk**](../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../README.md) / keys

# keys

Key generation utilities namespace

## Example

```typescript
import { keys } from '@open-e2ee/signal-protocol-sdk';
const identityKey = await keys.generateIdentityKeyPair();
const signedPreKey = await keys.generateEcSignedPreKey(signingKey);
```

## Interfaces

- [CompositeIdentityV1](interfaces/CompositeIdentityV1.md)
- [ContactIdentityRecord](interfaces/ContactIdentityRecord.md)
- [KemOneTimePreKey](interfaces/KemOneTimePreKey.md)

## Type Aliases

- [IdentityCandidateStatus](type-aliases/IdentityCandidateStatus.md)
- [IdentityTrustState](type-aliases/IdentityTrustState.md)
- [IdentityType](type-aliases/IdentityType.md)

## Variables

- [COMPOSITE\_IDENTITY\_V1\_ED25519\_TAG](variables/COMPOSITE_IDENTITY_V1_ED25519_TAG.md)
- [COMPOSITE\_IDENTITY\_V1\_LENGTH](variables/COMPOSITE_IDENTITY_V1_LENGTH.md)
- [COMPOSITE\_IDENTITY\_V1\_VERSION](variables/COMPOSITE_IDENTITY_V1_VERSION.md)
- [COMPOSITE\_IDENTITY\_V1\_X25519\_TAG](variables/COMPOSITE_IDENTITY_V1_X25519_TAG.md)
- [IDENTITY\_COMMITMENT\_V1\_DOMAIN](variables/IDENTITY_COMMITMENT_V1_DOMAIN.md)
- [PREKEY\_ALGORITHM\_ML\_KEM\_1024](variables/PREKEY_ALGORITHM_ML_KEM_1024.md)
- [PREKEY\_ALGORITHM\_X25519](variables/PREKEY_ALGORITHM_X25519.md)
- [PREKEY\_SIGNATURE\_V1\_DOMAIN](variables/PREKEY_SIGNATURE_V1_DOMAIN.md)
- [UNPINNED\_DEVICE\_IDENTITY\_KEY](variables/UNPINNED_DEVICE_IDENTITY_KEY.md)

## Functions

- [acceptContactIdentityRotation](functions/acceptContactIdentityRotation.md)
- [assertIdentityCommitment](functions/assertIdentityCommitment.md)
- [canonicalizeDeviceIdentityKey](functions/canonicalizeDeviceIdentityKey.md)
- [compareDeviceIdentityKeys](functions/compareDeviceIdentityKeys.md)
- [compositeIdentitiesEqual](functions/compositeIdentitiesEqual.md)
- [createCompositeIdentityV1](functions/createCompositeIdentityV1.md)
- [createPreKeySignatureContext](functions/createPreKeySignatureContext.md)
- [createUnverifiedContactIdentityRecord](functions/createUnverifiedContactIdentityRecord.md)
- [decodeCompositeIdentityV1](functions/decodeCompositeIdentityV1.md)
- [deriveIdentityCommitment](functions/deriveIdentityCommitment.md)
- [encodeCompositeIdentityV1](functions/encodeCompositeIdentityV1.md)
- [evaluateContactIdentityCandidate](functions/evaluateContactIdentityCandidate.md)
- [generateEcOneTimePreKeys](functions/generateEcOneTimePreKeys.md)
- [generateEcSignedPreKey](functions/generateEcSignedPreKey.md)
- [generateEcSignedPreKeyId](functions/generateEcSignedPreKeyId.md)
- [generateIdentityKeyPair](functions/generateIdentityKeyPair.md)
- [generateKemOneTimePreKeys](functions/generateKemOneTimePreKeys.md)
- [generateKyberLastResortPreKey](functions/generateKyberLastResortPreKey.md)
- [generateRegistrationId](functions/generateRegistrationId.md)
- [isValidDeviceIdentityKey](functions/isValidDeviceIdentityKey.md)
- [signMlKem1024PreKey](functions/signMlKem1024PreKey.md)
- [signPreKey](functions/signPreKey.md)
- [validateContactIdentityRecord](functions/validateContactIdentityRecord.md)
- [verifyContactIdentityRecord](functions/verifyContactIdentityRecord.md)
- [verifyMlKem1024PreKey](functions/verifyMlKem1024PreKey.md)
- [verifyPreKeySignature](functions/verifyPreKeySignature.md)

## References

### Ciphertext

Re-exports [Ciphertext](../../type-aliases/Ciphertext.md)

***

### EcOneTimePreKey

Re-exports [EcOneTimePreKey](../../interfaces/EcOneTimePreKey.md)

***

### EcSignedPreKey

Re-exports [EcSignedPreKey](../../interfaces/EcSignedPreKey.md)

***

### IdentityKeyPair

Re-exports [IdentityKeyPair](../../interfaces/IdentityKeyPair.md)

***

### KeyPair

Re-exports [KeyPair](../../interfaces/KeyPair.md)

***

### KyberPreKey

Re-exports [KyberPreKey](../../interfaces/KyberPreKey.md)

***

### PreKeyBundle

Renames and re-exports [RelayPreKeyBundle](../../interfaces/RelayPreKeyBundle.md)

***

### PrivateKey

Re-exports [PrivateKey](../../type-aliases/PrivateKey.md)

***

### PublicKey

Re-exports [PublicKey](../../type-aliases/PublicKey.md)

***

### Signature

Re-exports [Signature](../../type-aliases/Signature.md)
