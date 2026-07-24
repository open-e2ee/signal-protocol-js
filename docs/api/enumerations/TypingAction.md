[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / TypingAction

# Enumeration: TypingAction

Typing-indicator action enum.

Typing indicators are application-layer messages that use the same
encrypted messaging channel as regular messages, but are:
- Transient (not persisted)
- Real-time only (not queued if recipient offline)
- Privacy-respecting (mutual opt-in required)

## Enumeration Members

### STARTED

> **STARTED**: `0`

User started typing

***

### STOPPED

> **STOPPED**: `1`

User stopped typing (cleared input, sent message, or navigated away)
