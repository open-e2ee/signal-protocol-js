[**@open-e2ee/signal-protocol-sdk**](../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../README.md) / safety

# safety

Safety number utilities

Import directly from sub-path for cleaner imports:
```typescript
import { generateCompositeSafetyNumber, compareSafetyNumbers } from '@open-e2ee/signal-protocol-sdk/safety';
```

Or use namespace import:
```typescript
import { safety } from '@open-e2ee/signal-protocol-sdk';
safety.generateCompositeSafetyNumber(...);
```

## Classes

- [DisplayableFingerprint](classes/DisplayableFingerprint.md)
- [Fingerprint](classes/Fingerprint.md)
- [ScannableFingerprint](classes/ScannableFingerprint.md)

## Interfaces

- [FingerprintData](interfaces/FingerprintData.md)
- [SafetyNumber](interfaces/SafetyNumber.md)
- [VerifyLinkConfig](interfaces/VerifyLinkConfig.md)
- [VerifyUrlParams](interfaces/VerifyUrlParams.md)

## Type Aliases

- [CompareResult](type-aliases/CompareResult.md)

## Variables

- [DEFAULT\_VERIFY\_LINK\_CONFIG](variables/DEFAULT_VERIFY_LINK_CONFIG.md)
- [FINGERPRINT\_ITERATIONS](variables/FINGERPRINT_ITERATIONS.md)
- [FINGERPRINT\_VERSION](variables/FINGERPRINT_VERSION.md)
- [VERIFY\_BASE\_URL](variables/VERIFY_BASE_URL.md)
- [VERIFY\_SCHEME\_URL](variables/VERIFY_SCHEME_URL.md)

## Functions

- [base64ToBytes](functions/base64ToBytes.md)
- [clearFingerprintCache](functions/clearFingerprintCache.md)
- [compareSafetyNumbers](functions/compareSafetyNumbers.md)
- [createFingerprintData](functions/createFingerprintData.md)
- [extractQrData](functions/extractQrData.md)
- [generateCompositeSafetyNumber](functions/generateCompositeSafetyNumber.md)
- [generateEmojiFingerprint](functions/generateEmojiFingerprint.md)
- [generateSingleKeyReferenceSafetyNumber](functions/generateSingleKeyReferenceSafetyNumber.md)
- [generateVerifySchemeUrl](functions/generateVerifySchemeUrl.md)
- [generateVerifyUrl](functions/generateVerifyUrl.md)
- [isValidSafetyNumber](functions/isValidSafetyNumber.md)
- [isVerifyUrl](functions/isVerifyUrl.md)
- [parseVerifyUrl](functions/parseVerifyUrl.md)
