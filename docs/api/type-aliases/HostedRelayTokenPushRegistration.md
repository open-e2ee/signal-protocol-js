[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayTokenPushRegistration

# Type Alias: HostedRelayTokenPushRegistration

> **HostedRelayTokenPushRegistration** = \{ `platform`: `"ios"`; `profile`: `HostedRelayPushProfile`; `provider`: `"apns"` \| `"expo"`; `token`: `string`; \} \| \{ `platform`: `"android"`; `profile`: `"background-only"` \| `"visible-alert"`; `provider`: `"expo"` \| `"fcm"`; `token`: `string`; \}

Native or Expo provider token registered for this authenticated device.
