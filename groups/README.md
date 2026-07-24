# Groups

The groups module provides group identifiers, encrypted Groups V2 state,
membership transitions, access-control checks, invite links, and the
`GroupsV2Manager` orchestration API.

## Why it exists

Group state has a different lifecycle from pairwise sessions. The application
backend stores opaque encrypted group state and sequences changes, while each
member device owns group secrets, decrypted state, authorization credentials,
and sender-key rotation.

## Usage

```ts
import {
  GroupsV2Manager,
  createGroupId,
  type IGroupServer,
  type IGroupStateStore,
} from "@open-e2ee/signal-protocol-sdk/groups";

const groups = new GroupsV2Manager({
  store: appGroupStore as IGroupStateStore,
  server: appGroupServer as IGroupServer,
  issueCredential: () => appGroupCredentials.issue(),
  credentialPublicKey,
  aci: localAccountServiceId,
});

const groupId = createGroupId(rawGroupId);
const state = await groups.syncGroup(groupId);
```

The server must enforce authenticated access and version sequencing without
receiving plaintext group attributes or group master keys. Membership removal
must also invalidate or rotate group messaging state through the callbacks
required by `GroupsV2ManagerOptions`.

See the [API reference](../docs/api/README.md) and
[security model](../docs/SECURITY.md).
