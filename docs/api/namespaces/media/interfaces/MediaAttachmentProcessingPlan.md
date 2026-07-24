[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / MediaAttachmentProcessingPlan

# Interface: MediaAttachmentProcessingPlan

## Properties

### attachment

> **attachment**: [`MediaAttachmentPointer`](MediaAttachmentPointer.md)

***

### attachmentId

> **attachmentId**: `string`

***

### cleanup

> **cleanup**: [`MediaAttachmentCleanupPlan`](MediaAttachmentCleanupPlan.md) \| `null`

***

### deliveryId

> **deliveryId**: `string`

***

### downloadJob

> **downloadJob**: [`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md) \| `null`

***

### downloadReason

> **downloadReason**: `"new-delivery"` \| `"duplicate-missing-local-copy"` \| `null`

***

### hasLocalCopy

> **hasLocalCopy**: `boolean`

***

### isDuplicateDelivery

> **isDuplicateDelivery**: `boolean`

***

### isViewOnceOpened

> **isViewOnceOpened**: `boolean`

***

### shouldDownload

> **shouldDownload**: `boolean`

***

### shouldPersistMessage

> **shouldPersistMessage**: `boolean`
