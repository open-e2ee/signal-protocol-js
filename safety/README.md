# Safety Numbers

The safety module derives numeric, emoji, hexadecimal, and scannable
representations from two users' identity material.

## Why it exists

Trust-on-first-use detects later identity changes, but it does not prove who was
present at first contact. Safety numbers let users compare identity
commitments through a separate channel and record an explicit verification
decision.

## Usage

```ts
import { generateCompositeSafetyNumber } from "@open-e2ee/signal-protocol-sdk/safety";

const safetyNumber = generateCompositeSafetyNumber(
  localCompositeIdentity,
  remoteCompositeIdentity,
  localUserId,
  remoteUserId,
);

console.log(safetyNumber.numeric);
console.log(safetyNumber.emojis);

const comparison = safetyNumber.scannable.compare(scannedQrBytes);
if (comparison === "match") {
  await signal.verify(remoteAddress, remoteCompositeIdentity);
}
```

Use the composite safety-number API for contact verification in this SDK
profile. The single-key helper is a lower-level reference primitive and does
not authenticate the complete composite identity.

The SDK creates comparison data; the application owns QR rendering, scanning,
the verification user experience, and storage of the user's trust decision.

See the [keys guide](../keys/README.md) and
[security model](../docs/SECURITY.md).
