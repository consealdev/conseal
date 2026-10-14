# Channels

Shared encrypted spaces across users: everyone in a channel reads and writes with one key, the **channel AEK**, and the server stores only ciphertext and wrapped keys.

A channel builds on the circle. Each member holds the channel AEK wrapped under their own **circle AEK**, the key every device in their circle already has. Membership belongs to the user, not to a device:

```
Alice (phone + laptop) creates a channel
  → a random channel AEK, wrapped under Alice's circle AEK, stored as Alice's copy

Alice invites Bob (phone + laptop)
  → the invite runs between one of Alice's devices and one of Bob's
  → Bob's device wraps the channel AEK under Bob's circle AEK, stored as Bob's copy

Every device of either user: circle AEK → its user's copy → channel AEK
```

Bob is invited once, not once per device, and a device that joins his circle later opens every channel he is in, with no new invite. A circle is a prerequisite: a user sets up their circle before they create or join a channel.

## Signatures

```ts
createChannel(circleAEK: CryptoKey): Promise<{
  channelId: string
  channelAEK: CryptoKey
  wrappedChannelAEK: ArrayBuffer
  aekCommitment: ArrayBuffer
}>
unwrapChannelAEK(channelId: string, wrappedChannelAEK: ArrayBuffer | Uint8Array, circleAEK: CryptoKey): Promise<CryptoKey>

createChannelJoinRequest(channelId: string, aekCommitment: ArrayBuffer | Uint8Array): Promise<{
  request: ChannelJoinRequest
  ephemeralPrivateKey: CryptoKey
  verificationCode: string
}>
deriveChannelVerificationCode(joinRequest: ChannelJoinRequest, wrappedChannelAEK: ArrayBuffer | Uint8Array, circleAEK: CryptoKey): Promise<string>
authorizeChannelJoin(joinRequest: ChannelJoinRequest, wrappedChannelAEK: ArrayBuffer | Uint8Array, circleAEK: CryptoKey, serverReceivedAt: number): Promise<SealedAEK>
finalizeChannelJoin(sealedAEK: SealedAEK, ephemeralPrivateKey: CryptoKey, circleAEK: CryptoKey, channelId: string, aekCommitment: ArrayBuffer | Uint8Array): Promise<{
  channelAEK: CryptoKey
  wrappedChannelAEK: ArrayBuffer
}>

interface ChannelJoinRequest {
  channelId: string
  ephemeralPublicKey: JsonWebKey
}
```

`circleAEK` is the user's circle AEK as their device holds it, unwrapped: non-extractable is fine. `SealedAEK` is the circle's type.

## Example

```ts
import {
  createChannel, unwrapChannelAEK, seal, unseal,
  createChannelJoinRequest, deriveChannelVerificationCode, authorizeChannelJoin, finalizeChannelJoin,
} from '@consealdev/conseal'

// Alice creates a channel
const { channelId, channelAEK, wrappedChannelAEK, aekCommitment } = await createChannel(aliceCircleAEK)
// POST /channels { channelId, aekCommitment, wrappedChannelAEK } (Alice's copy)
const { ciphertext, iv } = await seal(channelAEK, plaintext)

// Any of Alice's devices, later
const key = await unwrapChannelAEK(channelId, aliceCopy, aliceCircleAEK)

// Bob, invited: the channel's id and commitment come first, then the request
const { request, ephemeralPrivateKey, verificationCode } = await createChannelJoinRequest(channelId, aekCommitment)
// POST /channels/:channelId/joins request — show verificationCode, keep the private key and commitment in memory

// Alice: the code for Bob's request, from her own copy of the key
const code = await deriveChannelVerificationCode(request, aliceCopy, aliceCircleAEK)
// Show code. Only once Alice and Bob confirm the codes match:
const sealedAEK = await authorizeChannelJoin(request, aliceCopy, aliceCircleAEK, serverReceivedAt)
// POST /channels/:channelId/joins/:joinId/authorize sealedAEK

// Bob, once he has confirmed the codes match and the sealed key has arrived
const { channelAEK: bobKey, wrappedChannelAEK: bobCopy } =
  await finalizeChannelJoin(sealedAEK, ephemeralPrivateKey, bobCircleAEK, channelId, aekCommitment)
// PUT /channels/:channelId/members/me bobCopy
```

## The invite

An invite is the circle's join ceremony between two users, with one change: the verification code covers the channel id and the channel's AEK commitment as well as the invitee's ephemeral public key. The request carries the public key, so anyone who relays it could seal a key of their own to it. What tells the invitee the key came from a member is that both screens show the same code:

- **The invitee** takes the channel's id and commitment, from the invite or the backend, before `createChannelJoinRequest` makes its key pair. The commitment is then fixed before the key exists, so whoever supplied it can't choose it to fit.
- **The member** gets their code from `deriveChannelVerificationCode`, which computes the commitment from the channel AEK they hold, never from a value the backend sends.
- A key substituted on the way, with a commitment to match, changes the invitee's code. A request whose public key was swapped changes the member's.

Rules the library can't enforce, so the app must:

- **Show the code on both sides, and require both users to confirm it matches.** The member confirms before `authorizeChannelJoin`; the invitee confirms before `finalizeChannelJoin`. The two users compare codes out-of-band: side by side, or on a call.
- Pass `serverReceivedAt` as the server's receipt time (Unix ms). Requests older than 5 minutes are refused.
- Pass `finalizeChannelJoin` the same commitment the request was created with, not one fetched again.
- Treat a channel's `aekCommitment` as immutable once stored.

`finalizeChannelJoin` throws if the key doesn't match the commitment. Store nothing then.

## Members leaving

Removal is the backend's: it stops serving the channel to the removed member (`403`) and deletes their copy. On a `403` from a channel route, the app clears the channel AEK and anything it cached from the channel.

A removed member keeps what they received while a member, and the channel AEK with it: removal locks them out of new data the server holds, not the keys or plaintext they already have. For a fresh key, create a new channel and invite the remaining members again; each member's copy is wrapped under their own circle AEK, so no member can re-wrap a new key for the others.

## Backend

The backend stores, per channel, the `aekCommitment` and one wrapped copy per member, and per pending invite the request with the time it received it, and the sealed key once a member authorizes. An app's routes look like these:

| Route | For |
|---|---|
| `POST /channels` | The creator: the channel id, its commitment and their copy |
| `GET /channels/:channelId` | An invitee: the commitment |
| `POST /channels/:channelId/joins` | An invitee: the request. The server stamps when it received it |
| `GET /channels/:channelId/joins` | Members: pending requests, with their receipt times |
| `POST /channels/:channelId/joins/:joinId/authorize` | A member: the sealed key |
| `GET /channels/:channelId/joins/:joinId` | The invitee: whether it's authorized, and the sealed key |
| `PUT /channels/:channelId/members/me` | The new member: their copy |
| `GET /users/me/channels` | Any device: every channel the user is in, with their copy |
| `DELETE /channels/:channelId/members/:memberId` | Removing a member |

A device that joins a circle calls `GET /users/me/channels` and opens each copy with the circle AEK. It needn't know beforehand which channels exist.

## Notes

- `channelAEK` is non-extractable. Seal content with `seal(channelAEK, …)`, or wrap per-item DEKs with it.
- A wrapped channel AEK is 60 bytes: IV (12) ‖ AES-GCM(circleAEK, channel AEK), AAD = UTF-8(`"conseal-channel:v1:" + channelId`). It opens only as the channel it was wrapped for, and can't pass for any other key the circle AEK wraps.
- A mnemonic recovery restores the circle AEK, and with it every channel copy.
- The verification code has the circle's format, `XXXX-XXXX-XXXX-XXXX`, but a different value for the same ephemeral key.
- Base64-encode the binary fields on the wire: `wrappedChannelAEK`, `aekCommitment`, and the `SealedAEK`'s `ciphertext` and `iv`.
