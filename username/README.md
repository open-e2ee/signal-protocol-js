# Usernames

The username module provides parsing, validation, formatting, hashing,
nickname generation, proof helpers, and encrypted username-link payloads.

## Why it exists

Usernames are discoverability identifiers, not cryptographic identities.
Keeping their normalization, proof, and share-link encoding in one module
helps applications avoid treating display text as a stable account identifier.

## Usage

```ts
import {
  formatUsername,
  hashUsername,
  parseUsername,
} from "@open-e2ee/signal-protocol-sdk/username";
import {
  createUsernameLink,
  decryptUsernameLink,
} from "@open-e2ee/signal-protocol-sdk/username/link";

const parsed = parseUsername("alice.42");
const canonical = formatUsername(parsed.nickname, parsed.discriminator);
const hash = hashUsername(parsed.nickname, parsed.discriminator);

const link = await createUsernameLink(canonical);
const recovered = await decryptUsernameLink(link);
```

Applications should store account identifiers separately from usernames.
Changing or deleting a username must not rotate the user's Signal Protocol
identity by implication.

See the [API reference](../docs/api/README.md).
