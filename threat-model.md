# Conseal Sync threat model

What the contract in [`openapi.yaml`](openapi.yaml) and [`circle.yaml`](circle.yaml) protects, what a server that
follows it still learns, and what a server that doesn't follow it can still do. It sits on top of conseal's own threat
model, which covers the keys, the circle and the join ceremony.

## Who is trusted

| Party | Trusted with |
|---|---|
| The user's devices | Plaintext and the AEK. A device that runs an attacker's script (XSS, a malicious extension) can use both, which is outside this model as it is outside conseal's |
| The sync server, its storage and its operator | Availability and honest ordering. Never with content: everything it stores is sealed before it leaves a device |
| The host app's sign-in | Which user a request belongs to. Whoever can sign in as the user can read and write their ciphertext, but not open it |
| The network | Nothing. TLS protects requests; presigned URLs carry their own short-lived authority |

## What the server learns

Sealing hides content, not the shape of the activity around it. A server that follows the contract still sees:

| It sees | Which tells it |
|---|---|
| The user id | Whose data it is |
| Collection ids | How many kinds of data the app keeps, though not what they are: ids are assigned, never names |
| Record ids | How many records each collection holds. Ids are random UUIDs, so they don't tell when a record was made |
| Ciphertext and blob sizes | Roughly how large each record and blob is. Nothing is padded |
| When each write, delete and pull happens | How active the user is, and when. `seq` orders writes; `deletedAt` and request times date them |
| Which records change together | Records pushed in one batch were probably edited together |
| The client's IP address and user agent | What the transport always shows |

It doesn't see the plaintext, field names, collection names, the AEK or any DEK, the merge's clocks, or how many
devices the user has. No vector clock travels in the clear, where it would count the user's devices and their edits:
the clocks a merge needs travel inside the ciphertext.

An app's privacy copy should state this list plainly rather than claim the server learns nothing.

## What the envelope stops

- **Reading.** Without the AEK the server can't open a DEK, and without a DEK it can't open a record or a blob.
- **Forging.** AES-GCM authenticates every record and blob. A ciphertext the server makes up, or alters by a bit, fails to
  unseal, and the client treats it as a bad record rather than data.
- **Moving.** The AAD names the collection and the record, and for a blob the blob too. A ciphertext copied to another
  record, collection or blob path fails to unseal there. The wrapped DEK carries the same AAD, so it can't be paired with
  another record's ciphertext either.
- **Forged cursors.** A cursor is signed by the server and tied to one user and collection, so a client can't build one
  to skip through the order, or reuse one across collections.

## What a dishonest server can still do

A server that breaks the contract can't read or forge, but it controls which genuine ciphertexts a client gets:

- **Roll back.** It can serve an older ciphertext of a record in place of the newest. The old one is genuine, so it
  unseals. A device that already holds the newer state keeps it if its merge policy compares versions inside the
  plaintext, as a field-level clock does; a last-write-wins policy, or a device syncing for the first time, takes the old
  one.
- **Withhold.** It can leave records out of a pull, or skip a range of `seq`, and the client can't tell a missing record
  from one never written.
- **Fork.** It can show two devices different histories, so they diverge without seeing a conflict.
- **Destroy.** It can delete records, or answer every push with a conflict so nothing is ever written.

Detecting these needs state the server doesn't control, such as per-device counters signed inside the plaintext. That
is not part of this version. Against an honest server they don't arise, and the contract's ordering rules exist so that
an honest server gives every device the same complete history.

## Replay

- **A replayed request** gains nothing. TLS stops a network attacker capturing one, and a replayed push names a
  `baseVersion` that is no longer current, so it gets a `409` instead of overwriting newer data.
- **A replayed cursor** only reads again from an earlier point, of the caller's own data.
- **A replayed record** is the rollback above: only the server can do it, and the envelope doesn't stop it.

## The conflict path

A `409` returns the server's current record so the client can merge. The merge runs on the client, on plaintext the
client has unsealed itself. So a conflict can't be used to make a client accept content the server made: `current`
must unseal under the record's AAD like any other record, and a client checks that `current.id` is the id it pushed.
What a dishonest server can do through a conflict is the same as above: hand back a stale `current` (rollback), or
answer `409` forever (destroy). A client that loops on conflicts for the same record should back off rather than spin.

A client that counted a `409` as a failure would stop syncing a record edited on two devices at once, for good and
without a word. So the contract makes a `409` a merge instruction, and keeps permanent failure for `400` and `413`.

## Deletes

A tombstone drops the record's ciphertext and the server deletes the record's blobs. The client can't check that the
server, its backups or its storage provider really erased them: a deleted record is unreadable without the AEK, not
proven gone.

## Blobs

- A presigned URL is a bearer token until it expires. Anyone holding it can fetch or replace that one blob's
  ciphertext, which they can't open. Keep the expiry short.
- An upload URL is signed for exactly the size the server agreed to, so a client can't store more than `maxBlobBytes`
  through it.
- Blobs go up before the record that refers to them, so a record whose push never happens leaves a blob behind. It is
  ciphertext and costs storage, not privacy. A server may delete blobs whose record never appears.

## The circle routes

[`circle.yaml`](circle.yaml) moves key material between a user's devices. Conseal's own threat model covers the
ceremony's cryptography; this section covers what the server holds and what the contract makes it refuse.

- **What it holds.** Each device's wrapped AEK, the AEK commitment, device names and platforms, and while a join waits,
  the new device's public key, then the AEK and a passphrase check sealed to that key. None of it opens without what
  stays on the devices: a passphrase and a Secret Key, or the new device's private key. The passphrase check is a
  salted PBKDF2 hash and travels sealed, so the server holds nothing to guess a passphrase against.
- **What it sees.** When devices join and are revoked, how many there are, and what their users call them.
- **A substituted key.** A dishonest server can replace a join request's public key with its own, to receive the AEK
  sealed to it. The verification code stops this: it is derived from the key, so the two devices show different codes,
  and the approving device seals nothing until the user has confirmed they match.
- **A substituted commitment.** A server that changes the commitment can make a key of its choosing pass a new device's
  check, so the commitment is written once. A server that lies about it from the start isn't stopped by this contract.
- **A replayed join.** A join request is used once and expires by the server's clock, so an old approval can't complete
  a later join.
- **A device added without the ceremony.** A save with no join request is how recovery works, and the server can't tell
  it from someone with the user's sign-in adding a device. That device holds nothing it can open, and the server tells
  the user, so a device they don't know is noticed and revoked.
- **Revoking.** A revoked device keeps the AEK it held (see *Out of scope*). The server deletes its wrapped AEK, refuses
  it from then on, and tells the user when it tries again.

## Out of scope

- A device that is compromised while unlocked: it holds the AEK.
- A weak passphrase, and losing the mnemonic: conseal's threat model covers both.
- Revoked devices: revoking a device stops it syncing but doesn't take back the AEK it held. Making a revoked device
  unable to read new data needs AEK rotation, which this version doesn't define.
- Denial of service, and the host app's sign-in itself.
