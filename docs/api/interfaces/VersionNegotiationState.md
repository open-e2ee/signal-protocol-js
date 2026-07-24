[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / VersionNegotiationState

# Interface: VersionNegotiationState

Version Negotiation State

Tracks the version negotiation process between two parties.
Transitions from StillNegotiating to NegotiationComplete exactly once.

With the binary wire format, version is implicit in byte 0 of every
message, so negotiation completes on first message received from the
peer. No separate capability exchange is needed.

## Example

```typescript
// Initialize in negotiating state
const versionNegotiation: VersionNegotiationState = {
  status: 'negotiating',
  maxVersion: 'v1',
  minVersion: 'v1',
};

// After receiving peer's first message with version byte
processVersionFromByte(versionNegotiation, peerVersionByte);
// versionNegotiation.status === 'complete'
// versionNegotiation.negotiatedVersion === 'v1'
```

## Properties

### maxVersion

> **maxVersion**: `"v1"`

Our maximum supported version.

Advertised to peer; negotiated version will be min(ours, theirs).

***

### minVersion

> **minVersion**: `"v1"`

Our minimum acceptable version.

If peer's max version is below this, negotiation fails.
Set to 'v1' to require post-quantum security.

***

### negotiatedVersion?

> `optional` **negotiatedVersion?**: `"v1"`

Negotiated version (set when status === 'complete').

The agreed-upon version for this session. Once set, cannot change.

***

### peerVersion?

> `optional` **peerVersion?**: `"v1"`

Peer's advertised maximum version (received from them).

Used to calculate negotiated version.

***

### status

> **status**: `"complete"` \| `"negotiating"`

Current negotiation status.

- `'negotiating'`: Waiting for peer's first message
- `'complete'`: Version agreed and locked for session
