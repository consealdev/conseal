# Channel AEK

A protocol extension that generalises the circle join mechanism from per-user device sync to shared encrypted spaces across multiple identities.

---

## Concept

The circle join ceremony is already a generic AEK distribution primitive. The only assumption it makes about the AEK being shared is that it is an AES-256-GCM key — it does not require that key to be the recipient's own identity AEK.

A **channel AEK** is a randomly generated AEK scoped to a named group rather than a single user's devices. Each member holds their own wrapped copy, sealed under their own passphrase and secret key. The server stores one wrapped copy per member, exactly as it does for device-scoped AEKs.

---

## Key differences from the user AEK

| | User AEK | Channel AEK |
|--|----------|-------------|
| Derived from | Mnemonic (deterministic) | Random (no recovery path needed) |
| Scope | One user, multiple devices | Multiple users, one channel |
| Recovery | Mnemonic re-derives the key | Any remaining member holds a valid copy |
| Rotation | Out of scope for v1 | On member removal (see below) |

---

## API extension

One new function is needed. The existing join ceremony functions require no changes — they already operate on an arbitrary `wrappedAEK`.

```typescript
/**
 * Creates a new channel with a randomly generated AEK.
 * The creator is the first member and holds the only initial wrapped copy.
 *
 * Unlike initCircle(), the AEK is not derived from a mnemonic —
 * recovery is handled by the fact that all members hold a wrapped copy.
 */
export async function createChannel(
  passphrase: string,
  secretKey: Uint8Array
): Promise<{ wrappedAEK: WrappedAEK; aekCommitment: ArrayBuffer; channelId: string }>
```

Inviting a member reuses the existing ceremony:

```
1. Invitee calls createJoinRequest()         — generates ephemeral key pair, verification code
2. Creator calls authorizeJoin()             — seals channel AEK for invitee's ephemeral key
3. Invitee calls finalizeJoin()              — unseals and re-wraps channel AEK under own credentials
```

The verification code exchange is unchanged — creator and invitee compare codes out-of-band before the channel AEK is transferred.

---

## Member removal

Removal is enforced at two layers:

- **Backend** — revokes the removed member's access to all channel endpoints (`403`). No new ciphertext reaches them.
- **Frontend** — on receiving `403` from any channel endpoint, clears the local channel AEK and any locally cached ciphertext.

The removed member retains whatever they received while a member. This is the same model as device removal in the circle — cryptographic lock-out of new data, not retroactive revocation of past access. For professional use cases this is an acceptable tradeoff; the member had legitimate access to that content during membership.

AEK rotation (generating a new channel AEK and re-sealing it for all remaining members) is a valid hardening step but is not required by the protocol. Implementors may offer it as an option for high-sensitivity channels.

---

## Backend

The channel backend follows the same shape as the circle backend — one wrapped AEK record per member, an `aekCommitment` set at channel creation, and the join challenge mechanism for invitations.

Channel endpoints are a parallel set to the circle endpoints:

```
POST   /channels/:channelId/members/join
GET    /channels/:channelId/members/join/:challengeId
POST   /channels/:channelId/members/join/:challengeId/authorize
POST   /channels/:channelId/members/:memberId/wrapped-aek
GET    /channels/:channelId/members/:memberId/wrapped-aek
DELETE /channels/:channelId/members/:memberId
GET    /channels/:channelId/members
```

`Conseal.Channel` and its storage adapters would be a natural addition to `conseal-server-dotnet` alongside `Conseal.Circle`.
