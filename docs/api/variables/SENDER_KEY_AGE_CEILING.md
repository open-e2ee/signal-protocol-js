[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SENDER\_KEY\_AGE\_CEILING

# Variable: SENDER\_KEY\_AGE\_CEILING

> `const` **SENDER\_KEY\_AGE\_CEILING**: `number`

Hard upper bound on [SenderKeysConfig.maxSenderKeyAge](../interfaces/SenderKeysConfig.md#maxsenderkeyage), in
milliseconds.

A sender key is the one piece of group key material that no ratchet
refreshes: it advances a chain forward on every send, so it gives forward
secrecy against a later compromise, but a member who holds the key at time
T can read everything sent under it afterwards. Only rotation ends that,
and rotation is what this bound guarantees eventually happens. Membership
changes normally force it sooner; the age bound is what covers a group
whose membership never changes.

Ninety days matches the ceiling the reference implementation applies to its
own remotely configured value. The difference here is who is being bounded:
the reference clamps a value it sets itself, whereas this SDK takes the
value from the host application, so the clamp is the only thing keeping a
deployment from disabling rotation outright by configuring an age no key
will reach.
