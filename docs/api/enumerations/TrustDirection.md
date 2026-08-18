[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / TrustDirection

# Enumeration: TrustDirection

## Enumeration Members

### RECEIVING

> **RECEIVING**: `"receiving"`

The client receives the message from the remote party.

Use more permissive verification:
- Allow receiving from new identities (TOFU)
- Allow receiving from changed identities with warning
- Maintain communication while alerting user to risks

***

### SENDING

> **SENDING**: `"sending"`

The client sends the message to the remote party.

Use stricter verification:
- Require explicit user trust for new identities
- Block sending if the identity key changed without user confirmation
- Prevent information leakage to potential attackers
