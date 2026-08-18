[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SENDER\_KEY\_AGE\_CEILING

# Variable: SENDER\_KEY\_AGE\_CEILING

> `const` **SENDER\_KEY\_AGE\_CEILING**: `number`

Hard upper bound on [SenderKeysConfig.maxSenderKeyAge](../interfaces/SenderKeysConfig.md#maxsenderkeyage), in
milliseconds.

A sender key is the one piece of group key material that no ratchet
refreshes. It advances a chain forward on every send, so it gives forward
secrecy against a later compromise. A member who holds the key at time T
can still read everything sent under it afterwards. Only rotation ends that,
and rotation is what this bound guarantees eventually happens. Membership
changes normally force it sooner. The age bound is what covers a group
whose membership never changes.

Ninety days matches the ceiling the reference implementation applies to its
own remotely configured value. The difference here is whose value the bound covers.
The reference clamps a value it sets itself, whereas this SDK takes the
value from the host application. The clamp is therefore the only thing that
keeps a deployment from disabling rotation outright by configuring an age
no key will reach.
