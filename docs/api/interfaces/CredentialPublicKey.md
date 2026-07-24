[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / CredentialPublicKey

# Interface: CredentialPublicKey

## Properties

### C\_W

> **C\_W**: `RistrettoPoint`

Commitment to W: C_W = W + wprime * G_wprime

***

### I

> **I**: `RistrettoPoint`[]

Iterative public-key images for different attribute counts.
I[0] is for numAttrs=2, I[5] is for numAttrs=7.
Length: NUM_SUPPORTED_ATTRS - 1 = 6
