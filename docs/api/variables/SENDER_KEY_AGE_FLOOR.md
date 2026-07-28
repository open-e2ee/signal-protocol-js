[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SENDER\_KEY\_AGE\_FLOOR

# Variable: SENDER\_KEY\_AGE\_FLOOR

> `const` **SENDER\_KEY\_AGE\_FLOOR**: `number`

Hard lower bound on [SenderKeysConfig.maxSenderKeyAge](../interfaces/SenderKeysConfig.md#maxsenderkeyage), in
milliseconds.

Unlike the ceiling this is not a security bound — rotating sooner is
strictly safer — it is an availability one, and it exists because expiry is
enforced on a key that a *send* has to rotate and redistribute. When a key
expires the send path generates a new one, fans a distribution message out
to every other member over sequential network calls, then retries the
encrypt, which re-checks the age of the key it just created. If the
configured age is shorter than that fan-out takes, the retry finds the new
key already expired and the send fails permanently, having burned a rotation
and a message to every member on each attempt.

An hour is well clear of that: even a group at the membership limit, with a
distribution message to each member, finishes its fan-out in minutes at
worst. It is also low enough to leave deliberately aggressive rotation
policies intact, which a bound measured in days would not.

A configured age below this is treated as the bound rather than rejected,
because the value that reaches it is usually a unit mistake — this field is
milliseconds, so a host that means fourteen days and passes `14` lands here
— and the safe reading of "rotate far more often than I asked" is to rotate
as often as the implementation can actually deliver.
