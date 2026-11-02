[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupReceiveDenial

# Type Alias: GroupReceiveDenial

> **GroupReceiveDenial** = `"malformed-context"` \| `"context-mismatch"` \| `"blocked"` \| `"sender-not-member"` \| `"recipient-not-member"` \| `"sender-lacks-permission"` \| [`GroupFetchDenial`](GroupFetchDenial.md) \| `"legacy-no-context"` \| `"configuration"` \| `"unverified-cap"` \| `"sync-from-other-account"`

Why the client delivers no group content and never will.

`legacy-no-context`: the content of a managed group carries no group
context. The client denies all such content, also when it has state of
the group. SDK 12.0.0 and later put the group context in group content,
so content from an SDK 11 sender is not delivered.
