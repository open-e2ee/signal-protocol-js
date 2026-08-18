[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / CompareResult

# Type Alias: CompareResult

> **CompareResult** = `"match"` \| `"no_match"` \| `"version_mismatch"`

Re-export fingerprint classes from fingerprint.ts

These provide a class-based API over the fingerprint primitives.
Use when you need:
- Object-oriented fingerprint manipulation
- Structured display and QR comparison
- Advanced operations (QR code scanning, etc.)

These classes expose single-key fingerprint primitives. Composite contact
verification must use SignalProtocolClient.verify(), which authenticates both
composite components and the locally pinned trust record.
