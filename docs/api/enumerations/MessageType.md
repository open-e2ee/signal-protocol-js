[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MessageType

# Enumeration: MessageType

## Enumeration Members

### PREKEY

> **PREKEY**: `"prekey"`

PreKey message for initial session establishment.

First message from initiator to responder. Contains extra information
needed for responder to establish session using X3DH/PQXDH.

***

### RATCHET

> **RATCHET**: `"ratchet"`

Regular Double Ratchet message.

Standard encrypted message using the Double Ratchet algorithm.
Use this after the session exists.
