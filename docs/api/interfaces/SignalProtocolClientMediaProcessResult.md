[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientMediaProcessResult

# Interface: SignalProtocolClientMediaProcessResult

## Properties

### abandoned

> **abandoned**: `number`

***

### attempted

> **attempted**: `number`

***

### completed

> **completed**: `number`

***

### expired

> **expired**: `number`

***

### failed

> **failed**: `number`

***

### results

> **results**: [`MediaAttachmentJobExecutionResult`](../namespaces/media/interfaces/MediaAttachmentJobExecutionResult.md)[]

***

### skipped

> **skipped**: `number`

***

### uploadFailures

> **uploadFailures**: `object`[]

Broker refusals that require explicit recovery with the original preparation.

#### failure

> **failure**: [`RemoteObjectUploadFailure`](RemoteObjectUploadFailure.md)

#### jobId

> **jobId**: `string`
