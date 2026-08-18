# Groups

The groups module provides group identifiers, encrypted group state,
membership transitions, access-control checks, invite links, and the
`GroupManager` orchestration API.

## Why it exists

Group state has a different lifecycle from pairwise sessions. The application
backend stores opaque encrypted group state and sequences changes, while each
member device owns group secrets, decrypted state, authorization credentials,
and sender-key rotation.

## Usage

```ts
import {
  GroupManager,
  createGroupId,
  type IGroupServer,
  type IGroupStateStore,
} from "@open-e2ee/signal-protocol-sdk/groups";

const groups = new GroupManager({
  store: appGroupStore as IGroupStateStore,
  server: appGroupServer as IGroupServer,
  issueCredential: () => appGroupCredentials.issue(),
  credentialPublicKey,
  serverSigningPublicKey,
  aci: localAccountServiceId,
  pni: localPhoneNumberServiceId,
  issueProfileKeyCredential: () => appGroupCredentials.issueProfileKey(),
  profileKeyCredentialPublicKey,
  profileKey: localProfileKey,
});

const groupId = createGroupId(rawGroupId);
const state = await groups.syncGroup(groupId);
```

The server must enforce authenticated access and version sequencing without
receiving plaintext group attributes or group master keys. Membership removal
must also invalidate or rotate group messaging state through the callbacks
required by `GroupManagerOptions`. Every `getGroup()` response must include a
baseline signature over the group ID, version, and exact encrypted-state bytes.
The client verifies that signature before installing a first or post-revocation
baseline.

Deployments whose server does not yet sign group changes must opt in explicitly
with `allowUnauthenticatedGroupHistory: true`. The SDK emits a security warning
because that mode has no authenticated group history.

See the [API reference](../docs/api/README.md) and
[security model](../docs/SECURITY.md).
