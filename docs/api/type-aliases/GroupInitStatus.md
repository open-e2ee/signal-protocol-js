[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupInitStatus

# Type Alias: GroupInitStatus

> **GroupInitStatus** = `"ready"` \| `"stale"` \| `"pending"` \| `"no-key"` \| `"denied"`

The init status of a group on this device.

- `'ready'`: the device holds the group key and the group state at the
  newest revision that it knows.
- `'stale'`: the device holds the group key and the group state, but a
  sender named a newer revision. The client fetches the newer state.
- `'pending'`: the device holds the group key and has no group state yet.
  The client fetches the state.
- `'no-key'`: the device knows the group but holds no group key. The client
  cannot fetch the group until the device gets the key.
- `'denied'`: the group server refused the newest revision that the device
  knows, for example because this account is not a member. A sender that
  names a newer revision makes the client try again.
