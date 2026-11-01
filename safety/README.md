# Safety Numbers

The safety module derives numeric, emoji, hexadecimal, and scannable
representations from two users' identity material.

## Why it exists

Trust-on-first-use detects later identity changes, but it does not prove who was
present at first contact. Safety numbers let users compare identity
commitments through a separate channel and record an explicit verification
decision.

## Usage

<!-- doc-snippet:skip requires-external-context -->
```ts
import { generateCompositeSafetyNumber } from "@open-e2ee/signal-protocol-sdk/safety";
import type { CompositeIdentityV1 } from "@open-e2ee/signal-protocol-sdk/keys";

export function compareCompositeIdentities(
  localCompositeIdentity: CompositeIdentityV1,
  remoteCompositeIdentity: CompositeIdentityV1,
  localUserId: string,
  remoteUserId: string,
  scannedQrBytes: Uint8Array,
): boolean {
  const safetyNumber = generateCompositeSafetyNumber(
    localCompositeIdentity,
    remoteCompositeIdentity,
    localUserId,
    remoteUserId,
  );
  console.log(safetyNumber.numeric);
  console.log(safetyNumber.emojis);
  return safetyNumber.scannable.compare(scannedQrBytes) === "match";
}
```

This helper comparison does not change a client's trust state. For an existing
client, compare the exact value returned by `verify()` through an authenticated
channel. Pass its original confirmation token only after that comparison succeeds.

<!-- doc-snippet:skip requires-authenticated-comparison -->
```ts
import type { DefaultSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";

type ComparisonDisplay = Pick<
  Awaited<ReturnType<DefaultSignalProtocolClient["verify"]>>,
  "numeric" | "fingerprint"
>;

export async function verifyContact(
  signal: DefaultSignalProtocolClient,
  remoteUserId: string,
  compareAuthenticated: (display: ComparisonDisplay) => Promise<boolean>,
): Promise<void> {
  const safetyNumber = await signal.verify(remoteUserId);
  const matched = await compareAuthenticated({
    numeric: safetyNumber.numeric,
    fingerprint: safetyNumber.fingerprint,
  });
  if (matched) {
    await signal.confirmSafetyNumber(safetyNumber.confirmation);
  }
}
```

The comparison callback belongs to the application. It must compare the displayed
numeric code or fingerprint with the same peer through an authenticated channel.
It must not approve a fresh client value because a separate helper value matched.

Use the composite safety-number API for contact verification in this SDK
profile. The single-key helper is a lower-level reference primitive and does
not authenticate the complete composite identity.

The SDK creates comparison data. The application owns QR rendering, scanning,
the verification user experience, and storage of the user's trust decision.

See the [keys guide](../keys/README.md) and
[security model](../docs/SECURITY.md).
