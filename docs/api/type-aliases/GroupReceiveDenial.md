[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupReceiveDenial

# Type Alias: GroupReceiveDenial

> **GroupReceiveDenial** = `"malformed-context"` \| `"context-mismatch"` \| `"blocked"` \| `"sender-not-member"` \| `"recipient-not-member"` \| `"sender-lacks-permission"` \| [`GroupFetchDenial`](GroupFetchDenial.md) \| `"legacy-no-context"` \| `"configuration"` \| `"unverified-cap"` \| `"sync-from-other-account"`

Why the client delivers no group content and never will.

`legacy-no-context`: the content of a managed group carries no group
context, and the client has no state of the group. SDK 12.0.0 and later
put the group context in group content. The next major SDK version no
longer decides group content that has no group context, so content from
an SDK 11 sender is not delivered. Move every sender to SDK 12.0.0 or
later before that version.
