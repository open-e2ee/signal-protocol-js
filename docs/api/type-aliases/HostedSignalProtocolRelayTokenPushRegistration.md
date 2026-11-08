[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayTokenPushRegistration

# Type Alias: HostedSignalProtocolRelayTokenPushRegistration

> **HostedSignalProtocolRelayTokenPushRegistration** = \{ `platform`: `"ios"`; `profile`: `HostedSignalProtocolRelayPushProfile`; `provider`: `"apns"` \| `"expo"`; `token`: `string`; \} \| \{ `platform`: `"android"`; `profile`: `"background-only"` \| `"visible-alert"`; `provider`: `"expo"` \| `"fcm"`; `token`: `string`; \}

Native or Expo provider token registered for this authenticated device.
