# Channel AEK + Circle Integration

How channel key distribution composes with the circle (multi-device) layer.

---

## The Layering Problem

The existing channel AEK proposal wraps the channel key under `passphrase + secretKey` — the same approach as the circle. That is device-scoped wrapping, which means User A's phone and laptop would each need separate channel memberships. This does not compose well at scale.

The cleaner model: wrap the channel AEK under the **user's circle AEK**, which is already shared across all their devices.

---

## Channel AEK Wrapped Under Circle AEK

Rather than wrapping the channel AEK under `passphrase + secretKey` (device-specific), wrap it under the user's `circleAEK` (user-bound, already device-synced):

```
circleAEK       = user's personal key, shared by all devices (mnemonic-derived)
channelAEK      = random key for the channel

wrappedChannelAEK = AES-GCM-encrypt(channelAEK, circleAEK)
                    stored once per user on the server
```

Any device of that user:
1. Unwraps their `wrappedAEK` → gets `circleAEK`
2. Fetches their `wrappedChannelAEK` → decrypts with `circleAEK` → gets `channelAEK`

**Member = user identity, not device.** The wrapping key shifts from `passphrase + secretKey` (device-bound) to `circleAEK` (user-bound, already device-synced).

The `createChannel` function signature simplifies accordingly — no `passphrase/secretKey` needed:

```typescript
export async function createChannel(
  circleAEK: CryptoKey   // already unwrapped by the caller
): Promise<{ wrappedChannelAEK: ArrayBuffer; channelAEK: CryptoKey; aekCommitment: ArrayBuffer; channelId: string }>
```

`finalizeJoin` for a channel produces a `wrappedChannelAEK` (AES-GCM under `circleAEK`) rather than the `WrappedAEK` struct with a `salt` (which is PBKDF2-derived and device-bound).

---

## The Full Multi-User Multi-Device Flow

```
User A (phone + laptop) creates channel
  → generates random channelAEK
  → wraps under A's circleAEK
  → stores on server as A's wrappedChannelAEK

User A invites User B (phone + laptop)
  → join ceremony runs between A's phone and B's phone (existing ceremony, unchanged)
  → B's phone receives channelAEK, wraps under B's circleAEK
  → stores on server as B's wrappedChannelAEK

Result:
  A's phone   → circleAEK → wrappedChannelAEK → channelAEK  ✓
  A's laptop  → circleAEK → wrappedChannelAEK → channelAEK  ✓
  B's phone   → circleAEK → wrappedChannelAEK → channelAEK  ✓
  B's laptop  → circleAEK → wrappedChannelAEK → channelAEK  ✓
```

The invite only needs to happen once per **user**, not once per device. Any device the user adds to their circle later picks up all channel keys automatically.

---

## Adding a Second Device After Joining a Channel

```
Step 1: Phone joins channel
  channelAEK → encrypted with circleAEK → wrappedChannelAEK stored on server
  (one record, belongs to the user, not the device)

Step 2: Laptop joins circle (normal circle ceremony)
  Phone authorizes laptop → laptop gets circleAEK → done

Step 3: Laptop accesses channel
  1. Fetches wrappedChannelAEK from server  ← already there
  2. Decrypts with circleAEK               ← already has it
  3. Has channelAEK ✓
```

No re-invitation. No extra ceremony. The laptop automatically has access to all channels the user belongs to.

**Prerequisite:** the user must have initialized their circle before accessing any channel. Circle setup is a prerequisite for channel access.

---

## The One Requirement

The server needs an endpoint returning all `wrappedChannelAEK` records for the authenticated user. A new device calls this after circle join completes, decrypts each entry with the `circleAEK`, and is fully synced.

```
GET /users/me/channels
→ [{ channelId, wrappedChannelAEK, aekCommitment, ... }, ...]
```

The new device does not need to know which channels exist ahead of time — it fetches the list and can decrypt all entries because it holds the `circleAEK`.

---

## Summary

| | Per-device wrapping (original proposal) | Per-user wrapping (this proposal) |
|--|--|--|
| Wrapping key | `passphrase + secretKey` | `circleAEK` |
| Server records | One per device per channel | One per user per channel |
| New device added | Must be re-invited to each channel | Automatic via circle join |
| Join ceremony | Once per device | Once per user |
