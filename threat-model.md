# conseal threat model

> **Version:** October 2026
> **Scope:** `@consealdev/conseal` with its `/sync` and `/ui` entry points, the wire contract in [`spec/`](spec), and
> backends that serve it, such as `ConsealDev.Conseal`
> **Audience:** integrators, security reviewers and auditors

What conseal protects, against whom, and what it relies on. Each section says what conseal enforces, what that
depends on, and what it leaves to the app. What conseal doesn't protect against, and what the app must provide for
any of this to hold, close the document (§11 to §13).

---

## 1. The system

conseal is end-to-end encryption on the user's device, built on the [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/)
(`SubtleCrypto`). Its central promise is **zero knowledge**: the server stores only ciphertext and wrapped keys, never
plaintext and never bare key material. Every cryptographic operation happens on the device.

It has three layers, one per entry point of `@consealdev/conseal`:

- **The core** (`@consealdev/conseal`): the primitives, the circle that shares a user's key between their devices, and
  channels that share a key between users.
- **Sync** (`@consealdev/conseal/sync`): `CircleClient`, which runs the circle's join ceremony against a backend, and
  `SyncEngine`, which moves the user's records between their devices as the contract in [`spec/`](spec) defines.
- **The ceremony screens** (`@consealdev/conseal/ui`): Lit components over `CircleClient`, with no crypto or HTTP of
  their own.

### Key assets

| Asset | Description | Where it lives |
|---|---|---|
| **AEK** (Account Encryption Key) | The user's root AES-256-GCM key. It seals their data, or the DEKs that seal it | Each device, as a non-extractable `CryptoKey` |
| **Wrapped AEK** | The AEK under PBKDF2 + AES-GCM, one per device | The server |
| **AEK commitment** | SHA-256 of the AEK | The server |
| **Secret Key (SK)** | A 128-bit second factor for wrapping the AEK | The device only, such as `localStorage` or a `CircleStore` |
| **Passphrase** | The user's chosen credential, combined with the SK in PBKDF2 | The user's memory |
| **BIP-39 mnemonic** | 24 words the AEK is derived from, kept as an offline backup | The user's written record only |
| **DEK** (Data Encryption Key) | A fresh AES-256-GCM key per record write and per blob, sealed under the AEK | Beside its ciphertext |
| **Plaintext** | The app's data before sealing | JavaScript memory, and with sync, the app's `RecordStore` (§6) |
| **Ciphertext** | AES-256-GCM sealed records and blobs | The server and its object storage |
| **Identity key pairs** | The user's ECDH and ECDSA key pairs, for messages sealed to them and signatures they make | Public keys wherever the app publishes them. Private keys on the device, and with sync in the `keyring` record (§7) |
| **Passphrase check** | A salted PBKDF2 hash of the approving device's passphrase, with a digest of the sealed AEK | Sealed to the joining device, only while a join runs |
| **Channel AEK** | An AES-256-GCM key shared by a channel's members, across users | Members' devices, as a non-extractable `CryptoKey` |
| **Wrapped channel AEK** | The channel AEK under one member's circle AEK (AES-GCM, bound to the channel id) | The server, one per member |
| **Sealed backup** | An export of the user's records, under a passcode | Wherever the user keeps it |

---

## 2. Who is trusted

| Party | Trusted with |
|---|---|
| The user's devices | Plaintext and the AEK. A device that runs an attacker's script (XSS, a malicious extension) can use both (§11.1) |
| The server, its storage and its operator | Availability and honest ordering. Never with content: everything it stores is sealed before it leaves a device |
| The host app's sign-in | Which user a request belongs to. Whoever can sign in as the user can read and write their ciphertext, but not open it |
| The network | Nothing. TLS protects requests, and presigned URLs carry their own short-lived authority |
| The browser's `SubtleCrypto` | Every cryptographic operation. A backdoored browser breaks everything (§12) |

---

## 3. Keys and their wrapping

### 3.1 A malicious or compromised server

**Capability:** full access to the database: ciphertext, wrapped keys, salts, commitments and public keys.

**What it gains:**
- Ciphertext, useless without the AEK.
- Each wrapped AEK and its salt, useless without the passphrase and the Secret Key.
- Public keys, which are not sensitive by design.
- Never the plaintext AEK, the Secret Key or the passphrase.

**The defence:** PBKDF2 at 600,000 HMAC-SHA-256 iterations makes offline passphrase guessing expensive. With a 128-bit
Secret Key, which never reaches the server, the server can't brute-force the wrapping key even with unlimited compute.

**Residual risk:** a weak passphrase without a Secret Key is only as strong as the passphrase. Callers should enforce a
minimum strength or mandate the Secret Key. What a server can do in a join, rather than offline, is §4.

### 3.2 Offline brute force against a stolen wrapped key

**Capability:** a dictionary or brute-force attack on a `{ wrappedKey, salt }` pair taken from the server or a backup.

**The defence:**
- PBKDF2 at 600,000 iterations costs about 200–500 ms per guess on modern hardware.
- A 128-bit random Secret Key raises the key space to 2¹²⁸ × the passphrase space, out of reach even for specialised
  hardware.
- Each wrap has its own random salt, so precomputed (rainbow table) attacks don't apply.

### 3.3 Tampering with ciphertext

**Capability:** flip bits in a stored or transmitted ciphertext.

**The defence:** AES-256-GCM is authenticated. Any change to the ciphertext, the IV or the AAD makes `unseal()`,
`unsealMessage()` and `unsealEnvelope()` throw, and the tampered bytes never reach the caller. There is no
decrypt-and-ignore-the-tag path. §6.1 says what the AAD adds for records and blobs.

### 3.4 A network attacker

**Capability:** watch or change HTTP traffic.

**With TLS** the attacker sees ciphertext and wrapped keys only. **Without TLS** they can serve a malicious JavaScript
bundle and defeat everything. conseal doesn't manage transport: callers **must** serve their app over HTTPS.

### 3.5 The library leaking keys

**Concern:** that conseal sends key material somewhere.

**The defence:** conseal is open source and auditable. Its core makes no network requests. Sync makes only the
requests the app's transport sends, to the app's own backend, and carries no key the server could open. Key material
goes only to `SubtleCrypto`, which enforces `extractable: false` on stored keys, so no JavaScript, conseal's included,
can read their bytes out of IndexedDB.

### 3.6 Algorithms

| Primitive | Algorithm | Parameters | Why |
|---|---|---|---|
| Symmetric encryption | AES-GCM | 256-bit key, 12-byte IV, 128-bit tag | NIST standard; authenticated; hardware-accelerated in all modern CPUs and browsers |
| Key derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations, 16-byte random salt | RFC 8018; NIST SP 800-132 recommends ≥ 210,000 for SHA-256; broad browser support |
| Key wrapping | AES-GCM | 256-bit wrapping key from PBKDF2, 12-byte random IV before the wrapped key, 128-bit tag | Authenticated on every engine, so a wrong passphrase or Secret Key throws. Not AES-KW: WebKit doesn't enforce its integrity check, so a wrong credential could return garbage instead of throwing |
| Key agreement | ECDH | NIST P-256 | Widely available in `SubtleCrypto`; adequate for this model; no dependencies |
| Signatures | ECDSA | NIST P-256, SHA-256 | As ECDH; P-256 is WebCrypto's baseline curve |
| Hashing | SHA-256 | — | Universal; PBKDF2's PRF and the standalone digest |
| Mnemonic encoding | BIP-39 | 24 words (256-bit entropy + 8-bit checksum) | A human-writeable offline backup; well specified; implemented by `@scure/bip39` |
| Mnemonic to AEK | HKDF-SHA-256 | Empty salt, info `conseal-mnemonic-aek-v1` | The entropy is already uniform; the label keeps this key apart from any other use of the same entropy |
| Verification code | SHA-256 | First 80 bits, as 16 Crockford base32 characters: `XXXX-XXXX-XXXX-XXXX` | A server relaying a join needs a key whose code matches: 2⁸⁰ tries is out of reach live and as a precomputed table, where 32 bits falls to one GPU in under a minute. The alphabet has no I, L, O or U, so no two characters look alike |
| Passphrase check | PBKDF2-HMAC-SHA256 | 200,000 iterations, random salt | Lets the joining device confirm the passphrase, sealed so the server can't guess against it (§4.2) |
| Records and blobs | AES-GCM | A fresh 256-bit DEK per write and per blob, AAD `conseal-sync:v1:<collectionId>:<recordId>`, and `:<blobId>` for a blob | Binds each ciphertext to its place (§6.1) |
| Sealed backup | AES-GCM | A random key wrapped like the AEK, one AES-GCM chunk per 1 MiB, each with an AAD naming the backup, the chunk's place and whether it's the last | Streams both ways, and a changed, dropped, moved or truncated chunk fails (§9) |
| Randomness | `crypto.getRandomValues` | — | A CSPRNG from the browser or OS; no user-space RNG |

---

## 4. The circle

The circle is the set of a user's devices that hold the AEK. The AEK reaches a new device only when the user approves
it on a device that already holds it. On the way, the server relays ciphertext, wrapped keys, salts, public keys and
the AEK commitment, and nothing it could open or guess a passphrase against.

The ceremony: the new device reads the AEK commitment, then posts a join request with an ephemeral ECDH public key, and
both devices show a verification code derived from the commitment and that key. Once the user confirms the codes match,
the approving device seals the AEK to that key, and the new device unseals it, checks it, and wraps it under its own
passphrase and Secret Key.

### 4.1 What the core enforces

- **The verification code.** Each device shows 80 bits of the SHA-256 of a label, the AEK commitment and the
  ephemeral public key. The new device takes the commitment before its key pair exists, so whoever supplies it can't
  choose it after seeing the key, and the approving device uses its own, never one the server supplies with the
  request. The server relays the request, so it can put a key of its own in its place and receive the AEK sealed to
  it, or give the new device the commitment of a key of its own and seal that key to the request. Either changes one
  device's code. The user approves only when the codes match, and a server needs a match by chance: about 2⁸⁰ tries,
  out of reach both within the request's five minutes and as a table built in advance for the account's commitment.
- **The commitment.** `finalizeJoin` checks the AEK it unseals against the commitment the request was created with,
  which the code covers. A mismatch throws, and nothing is wrapped.
- **The server's receipt time.** `authorizeJoin` refuses a request the server received more than five minutes earlier.
  It takes `serverReceivedAt`, the time the server says it received the request, never the request's own `createdAt`,
  which the joining device sets.

### 4.2 What `CircleClient` adds

`CircleClient`, in `@consealdev/conseal/sync`, runs the ceremony against a backend that serves the circle routes of
the spec.

- **The code comparison is said out loud.** `approveJoin` takes `codeConfirmed: true`, so an app can't approve
  without saying the user compared the codes. The comparison itself is the user's, and the library can't make them
  look. A UI that approves without showing the code, or confirms on the user's behalf, removes the defence in §4.1: a
  server that swaps in its own key then receives the AEK.
- **The approving device's own commitment.** A device keeps the commitment it took the AEK with, at setup, joining
  or recovery, and `pendingJoins` derives the codes from it. A device set up before it kept one reads as locked until
  its next unlock, which works the commitment out from the AEK.
- **A key from a device that knows the passphrase.** The request's ephemeral public key is public: the server relays
  it, so it can seal a key of its own to it and answer the join itself, with no approving device. The new device's
  code then covers that key's commitment, but no trusted device shows a code to compare, and a user who sees the new
  device move on may finish the join. The joining device therefore takes the AEK only with the approving device's
  passphrase check, and the check vouches for that one
  sealed AEK: it carries a SHA-256 of the sealed AEK's IV and ciphertext. A server without the passphrase can't make a
  check that passes, and can't move a real check onto a key of its own, since the check travels sealed. An approval
  with no check, a check that doesn't open, or one that vouches for another key fails the join with
  `UnverifiedKeyError`, and nothing is registered or kept.
- **The passphrase check itself.** The approving device sends a salted PBKDF2-SHA-256 hash of its passphrase (200,000
  iterations), with the digest of the sealed AEK, sealed to the joining device's ephemeral key. The joining device
  asks for the same passphrase and refuses another with `WrongPassphraseError`, so the user can try again. The server
  relays ciphertext. The joining device can guess against the hash, but it is the user's own device, about to hold
  the same passphrase.
- **The commitment, when joining.** `startJoin` reads the account's commitment before it makes the key pair, and
  doesn't take the one `createJoin` answers with. The joining device checks the AEK it receives against it. A mismatch
  fails the join with `CommitmentMismatchError`, and nothing is registered or kept.
- **The commitment, when recovering.** `recover` checks the key derived from the mnemonic against the commitment
  before it registers anything. A mistyped phrase that still passes the BIP-39 checksum, as about one single-word
  typo in 256 does, is refused, so it can't replace the circle's key or, with `revokeOtherDevices`, lock the other
  devices out.
- **Short-lived keys.** The joining device's ephemeral private key lives only in its `JoinSession`, in memory, and is
  dropped when the session ends. `setup` returns the mnemonic once and never stores or sends it.

### 4.3 The core functions without `CircleClient`

An app on the core functions alone gets the code comparison of §4.1, as long as the new device takes the commitment
before `createJoinRequest` and the approving device derives its code from its own commitment, the one `initCircle`
returned or its own join or recovery checked. A server that gives the new device another key's commitment then
changes the new device's code.

What the core doesn't add is the passphrase check (§4.2). A server can still answer a join itself, with a key of its
own and that key's commitment, and no trusted device then shows a code. A new device that finishes without the user
having confirmed matching codes on a trusted device takes the server's key, and the server reads everything it seals.
So the new device finishes only once the user has confirmed the codes match, as a channel invite does (§5.2), or
checks where the AEK came from as `CircleClient` does.

### 4.4 What the server holds and refuses

The circle routes are [`spec/circle.yaml`](spec/circle.yaml).

- **What it holds.** Each device's wrapped AEK, the AEK commitment, device names and platforms, and while a join
  waits, the new device's public key, then the AEK and a passphrase check sealed to that key. None of it opens without
  what stays on the devices: a passphrase and a Secret Key, or the new device's private key.
- **What it sees.** When devices join and are revoked, how many there are, and what their users call them.
- **A substituted commitment.** The commitment is written once. A server that changes it, or lies about it from the
  start, can make every join fail. It can't make a device take a key of its own that way: the codes cover the
  commitment, so a lie shows as codes that differ, and the passphrase check decides which key a new device takes.
- **A replayed join.** A join request is used once and expires by the server's clock, so an old approval can't
  complete a later join. A dishonest server can keep a request open longer; approving it still needs the code
  comparison.
- **A device added without the ceremony.** A save with no join request is how setup and recovery work, and the server
  can't tell it from someone with the user's sign-in adding a device. That device holds a wrapped AEK only its own
  passphrase and Secret Key open, so it gains no access, and the server tells the user, so a device they don't know is
  noticed and revoked.
- **Revoking.** The server deletes the revoked device's wrapped AEK, refuses it from then on, and tells the user when
  it tries again. The device keeps the AEK it held (§4.6).

### 4.5 What it relies on

- **The code comparison.** A server that swaps the request's public key for its own receives the AEK, and a
  passphrase check it can open and guess against offline. Only the user comparing the whole code stops that. An app
  that approves a join without the user comparing it loses the join's defence.
- **A passphrase the server wouldn't guess.** A dishonest server can make up a check for a passphrase it guesses and
  seal a key of its own with it. The join then passes only if the user types that same passphrase. Each guess costs
  the server a join the user starts, and a wrong one shows as a wrong passphrase. As long as the codes are compared,
  the server holds nothing to test guesses against offline.
- **Keys at rest.** The device keeps its Secret Key, its wrapped AEK and, while unlocked, the AEK as a non-extractable
  `CryptoKey`, in its `CircleStore`, IndexedDB by default. A script running in the page can use the AEK and read the
  Secret Key (§11.1).
- **The sign-in.** Setup and recovery register a device on the strength of the user's sign-in alone. Such a device
  gains no access, but the device list is only as trustworthy as the sign-in.

### 4.6 What it doesn't do

- **Rotate keys.** A revoked device stops syncing but keeps the AEK it held, and can open everything sealed under it.
  Making a revoked device unable to read new data needs AEK rotation, which this version doesn't define.
- **Guarantee availability.** The server can refuse, deny or expire any join, and withhold the device list.

---

## 5. Channels

A channel is a shared encrypted space across users: its members read and write with one random channel AEK. Each member
holds it wrapped under their own circle AEK, so every device in their circle opens it. An invite runs the circle's
join ceremony between two users.

### 5.1 What the server holds

Per channel, the AEK commitment (SHA-256 of the channel AEK) and one wrapped copy per member. Per pending invite, the
invitee's ephemeral public key and, once a member authorizes it, the channel AEK sealed to that key. None of it opens
without a member's circle AEK or the invitee's ephemeral private key.

### 5.2 What conseal enforces

- **Copies bound to their channel.** A wrapped copy carries the channel id in its AAD. The server can't serve one
  channel's copy as another's, or pass any other key the circle AEK wraps off as a channel AEK.
- **The commitment, at the invite.** The invitee checks the key it receives against the commitment it took before
  making its request. A mismatch throws, and nothing is stored.
- **A code that covers the commitment.** The invite's verification code is derived from the channel id, the commitment
  and the invitee's ephemeral public key, and the member's side computes the commitment from the key it holds. The
  request's public key is public, so a server that relays it can seal a key of its own to it and give the invitee a
  commitment to match; the two codes then differ. A swapped public key changes the member's code.
- **Fresh requests.** `authorizeChannelJoin` refuses a request the server received more than five minutes earlier.

### 5.3 What it relies on

- **The code comparison, on both sides.** The member confirms the codes match before authorizing, the invitee before
  finalizing. Without the member's confirmation, the channel AEK can go to a key the server holds; without the
  invitee's, the invitee can accept a key the server chose.
- **The server's receipt time,** passed as `serverReceivedAt`, never a time the invitee supplied.
- **The backend, for membership.** Removing a member is access control: the server stops serving them the channel.
  They keep the channel AEK and everything they received while a member. A fresh key means a new channel and new
  invites.
- **Each member's circle.** A copy is as safe as the circle AEK it is wrapped under: whoever can use a member's circle
  AEK opens every channel the member is in.

### 5.4 What the server still learns

Who is in which channel, when invites happen, and the size and timing of what members write. Channels hide content,
not membership (§10).

---

## 6. Sync

`SyncEngine` moves records between the user's devices as the contract in [`spec/openapi.yaml`](spec/openapi.yaml)
defines: each write sealed under a fresh DEK, the DEK sealed under the AEK, both bound to the record by the AAD
`conseal-sync:v1:<collectionId>:<recordId>`.

### 6.1 What the envelope stops

- **Reading.** Without the AEK the server can't open a DEK, and without a DEK it can't open a record or a blob.
- **Forging.** AES-GCM authenticates every record and blob. A ciphertext the server makes up, or alters by a bit,
  fails to unseal, and the client treats it as a bad record rather than data.
- **Moving.** The AAD names the collection and the record, and for a blob the blob too. A ciphertext copied to another
  record, collection or blob path fails to unseal there. The wrapped DEK carries the same AAD, so it can't be paired
  with another record's ciphertext either.
- **Forged cursors.** A cursor is signed by the server and tied to one user and collection, so a client can't build
  one to skip through the order, or reuse one across collections.

### 6.2 What `SyncEngine` enforces

- **Nothing in the clear but the contract's fields.** A push carries the record id, the server's version and the
  three envelope fields. No clock, timestamp, device id or field name travels outside the ciphertext. The
  `schemaVersion` is sealed inside it.
- **Local-only fields stay local.** Fields a collection lists as `localOnly` are removed before sealing, and kept from
  this device's copy on every merge, so another device's value never replaces them.
- **Ids that tell nothing.** `save` refuses any id but a lowercase random UUID, so an app can't use a provider's file
  id, or a time-ordered UUID, as a record id the server sees.
- **A record opens only where it was sealed.** The engine opens every pulled record and every conflict's current
  record under its own collection and id. A ciphertext the server altered, moved from another record or collection,
  or that another AEK sealed, fails to open: the engine skips it, reports it as `unreadable`, and applies the rest.
- **A conflict is a merge.** A `409`'s current record is checked to be the record pushed, opened, and merged with the
  local copy by the collection's policy on plaintext; the result is sealed afresh, under a new DEK, and pushed against
  the current version. A push that conflicts again goes again, up to three rounds per sync, so a server that answers
  every push with a conflict costs three requests a sync rather than a loop.
- **An unreadable conflict isn't overwritten.** When a conflict's current record doesn't open, the engine has nothing
  to merge with. It stops retrying that record (`unreadable_conflict`) rather than push over it: if the fault is this
  device's, such as a wrong key, overwriting would destroy what another device wrote.
- **Permanent failures stop.** A `400` or a `413`, or a record over `maxRecordBytes` before it's sent, stops that
  record's retries until the app changes it, and is reported as `rejected`. Transient failures leave it pending for
  the next sync.
- **Only the server's cursor.** The engine resumes pulls from the cursor the server last gave it, never from its own
  clock. A cursor the server refuses means starting from the beginning, which merges idempotently: a pulled record
  whose version this device already holds is skipped.
- **No lost edits.** Every write to the local store is a compare-and-set on the record's `rev`, so a pull or a push
  result never overwrites a change the app made while it was in flight.

### 6.3 What a dishonest server can still do

A server that breaks the contract can't read or forge, but it controls which genuine ciphertexts a client gets:

- **Roll back.** It can serve an older ciphertext of a record in place of the newest. The old one is genuine, so it
  unseals. A device that already holds the newer state keeps it if its merge policy compares versions inside the
  plaintext, as a field-level clock does; a last-write-wins policy, or a device syncing for the first time, takes the
  old one.
- **Withhold.** It can leave records out of a pull, or skip a range of `seq`, and the client can't tell a missing record
  from one never written.
- **Fork.** It can show two devices different histories, so they diverge without seeing a conflict.
- **Destroy.** It can delete records, or answer every push with a conflict so nothing is ever written.

Detecting these needs state the server doesn't control, such as per-device counters signed inside the plaintext. That
is not part of this version. Against an honest server they don't arise: the contract's ordering rules exist so that an
honest server gives every device the same complete history.

### 6.4 Replay

- **A replayed request** gains nothing. TLS stops a network attacker capturing one, and a replayed push names a
  `baseVersion` that is no longer current, so it gets a `409` instead of overwriting newer data.
- **A replayed cursor** only reads again from an earlier point, of the caller's own data.
- **A replayed record** is the rollback in §6.3: only the server can do it, and the envelope doesn't stop it.

### 6.5 The conflict path

A `409` returns the server's current record so the client can merge. The merge runs on the client, on plaintext the
client has unsealed itself. So a conflict can't make a client accept content the server made: `current` must unseal
under the record's AAD like any other record, and the client checks that `current.id` is the id it pushed. What a
dishonest server can do through a conflict is the same as §6.3: hand back a stale `current` (rollback), or answer
`409` forever (destroy). A client that loops on conflicts for the same record should back off rather than spin, as
`SyncEngine` does after three rounds.

A client that counted a `409` as a failure would stop syncing a record edited on two devices at once, for good and
without a word. So the contract makes a `409` a merge instruction, and keeps permanent failure for `400` and `413`.

### 6.6 Deletes

A tombstone drops the record's ciphertext, and the server deletes the record's blobs. The client can't check that the
server, its backups or its storage provider really erased them: a deleted record is unreadable without the AEK, not
proven gone.

### 6.7 What it relies on

- **The merge policy.** Every remote change to a record this device holds goes through the collection's policy,
  pending or not, with `pending` saying which. A policy that compares versions inside the plaintext, such as a
  field-level clock, keeps the newer value when a dishonest server serves a stale one, and the engine pushes it back.
  The built-in `lastWriteWins` compares nothing: with no change pending, it takes the server's value, stale or not.
  Pick it for data where that's acceptable.
- **Plaintext at rest.** Records are plaintext in the app's `RecordStore`, by design: queries, indexes and merges run
  on them, and encryption happens at the network boundary. Anything that can read the app's storage reads the
  records.
- **The `Keyring`.** The engine asks it for the AEK at the start of every sync and holds the AEK only for that sync. A
  locked `Keyring` stops the sync before anything is sent.
- **One engine per store.** The compare-and-set protects writes from the app and the engine, and from two engines
  sharing one store. Two `sync` calls on one engine share a run; two engines syncing one store at once, such as two
  tabs, can push the same change twice, which the server answers with a conflict that merges to the same value.

### 6.8 What it doesn't do

- **Detect withheld or forked history** (§6.3).
- **Hide activity.** Pushes happen when the app calls `sync`, a batch shows which records changed together, and record
  sizes aren't padded (§10).
- **Rotate keys.** A revoked device keeps the AEK it held, and every record sealed under it.

---

## 7. The identity

`identity` gives every device in the circle the same ECDH and ECDSA key pairs, so a message sealed to the user opens on
any of their devices, and outlives the device that set the circle up. The pairs travel in the keyring, the one record
of the contract's reserved `keyring` collection, sealed under the AEK like any record, so the server holds it without
being able to open it.

### 7.1 What `SyncEngine` enforces

- **One identity, made once.** A sync creates the keyring only when it finds none on the server and none on the device,
  and pushes it under the contract's fixed id with no base version. Two devices that create one at once push the same
  record, so one push conflicts, and that device takes the other's keyring in place of its own.
- **Nothing handed out early.** `identity` returns key pairs only once the server has taken them. A keyring this
  device made and hasn't pushed yet could still lose to another device's, and a message sealed to it would then open
  nowhere.
- **A keyring that doesn't open isn't replaced.** When the server's keyring doesn't open under the AEK, this device's
  own goes up with no base version, conflicts, and stops retrying (`unreadable_conflict`), as any unreadable conflict
  does. `identity` throws `KeyringError`, and the server's record stays: if the fault is this device's, such as a wrong
  key, the identity every other device holds isn't overwritten. A keyring the server sealed itself is refused the same
  way, so a server can't make a client take an identity of its own.
- **Out of the app's reach.** No registry collection may be named `keyring` or take its id, so `get`, `save`,
  `remove` and `importAll` never reach it, and a crafted export can't plant an identity. Sync events and the report's
  counts leave it out, so its private keys never reach a listener.
- **Out of every export.** Exports and backups hold the registry's collections only. A file that carried the keyring
  would let whoever got it open every message sealed to the user.

### 7.2 What it relies on

- **Plaintext at rest.** On the device the keyring is a record like any other: the private keys sit as JWKs in the
  app's `RecordStore`, in plaintext. `identity` imports them as non-extractable `CryptoKey`s, which keeps them out of
  what the app passes around, not out of the store. A script that can read the app's storage reads them, as it could
  open the keyring with the AEK anyway.
- **An honest server, for one identity.** A server that hides the keyring from a device makes that device create a
  second one, and can later serve either to either device. Both are the user's own, made on their devices, so this
  costs messages, not secrecy: a message sealed to one doesn't open with the other. Against an honest server the fixed
  record id and the `409` leave the user with one identity.
- **The server, to keep it.** A recovery from the mnemonic gets the identity back from the server's copy. The mnemonic
  derives the AEK, not the identity, so if the server's copy is gone, so is the identity.

### 7.3 What it doesn't do

- **Rotate the identity.** A revoked device keeps it, as it keeps the AEK.
- **Vouch for the public keys.** Where others find the user's public keys, and how they know the keys are the user's,
  is the app's.
- **Hide that it exists.** The server learns that the user has an identity, and when it was made: the record's write is
  dated like any other.

---

## 8. Blobs

A blob holds content too large for a record: a random 12-byte IV, then AES-GCM of its bytes under a DEK of its own,
with the AAD `conseal-sync:v1:<collectionId>:<recordId>:<blobId>`. Its DEK travels only in the reference the app puts in
the record's value, so it is sealed under the AEK with the record. The bytes move straight between the device and
object storage, through presigned URLs.

### 8.1 What `SyncEngine` enforces

- **A fresh DEK per blob,** made on the device, and sent nowhere but inside its record's ciphertext.
- **A blob opens only where it was sealed.** The AAD names the collection, the record and the blob id, and the
  reference gives the size: a blob the server altered, moved from another record or id, or swapped for another of the
  user's blobs fails to open, with `UnreadableRecordError`.
- **No reference before its blob.** A sync uploads every blob waiting in a collection before it pushes the
  collection's records, and an upload that fails stops the push. A device that pulls a record finds its blobs there,
  unless they were deleted since.
- **Deletes after the record.** A detached blob is deleted from the server only once its record is pushed without the
  reference.
- **No sign-in sent to storage.** `FetchSyncTransport` sends presigned requests through `blobFetch`, the global `fetch`
  by default, so the app's sign-in never reaches object storage, and refuses a blob URL for another method than the
  one it asked for.

### 8.2 What the contract adds

- **A presigned URL is a bearer token until it expires.** Anyone holding it can fetch or replace that one blob's
  ciphertext, which they can't open. Keep the expiry short.
- **An upload URL is signed for exactly the size the server agreed to,** so a client can't store more than
  `maxBlobBytes` through it.

### 8.3 What it relies on

- **The app's references.** The engine finds references by their shape anywhere in a value. The app keeps them in what
  it saves, and its merge policy decides which survive a merge: one that keeps a reference to a detached blob gets
  `BlobNotFoundError` on the other devices, and one that drops a reference leaves the blob on the server until it's
  detached or its record deleted.
- **The device's storage.** A blob waiting to upload sits sealed in the `RecordStore`, with its DEK beside it in the
  record's plaintext value. Anything that can read the app's storage reads it, as it reads the records.
- **The backend's storage rules.** The server presigns each upload for the sealed size it was told; the bucket's CORS
  rules, access policies and the lifetime of its URLs are the backend's.

### 8.4 What it doesn't do

- **Hide sizes or timing.** Uploads happen when the app syncs, and a blob's size reaches the server unpadded.
- **Cache downloads.** `openBlob` keeps nothing it downloads. Where the app keeps the bytes is the app's, and so is how
  it protects them.
- **Collect orphans.** Blobs go up before the record that refers to them, so a blob whose record never arrives, or whose
  reference a merge dropped, stays on the server. It is ciphertext and costs storage, not privacy, and a server may
  delete blobs whose record never appears.

---

## 9. Export and import

`exportAll` writes this device's records to a file the user keeps, and `importAll` reads one back. They exist so the
user controls their data, not only holds the keys to it: if the app goes away, the server's copy can't be read.

### 9.1 What they enforce

- **Content, never keys.** An export holds record values, the blobs they refer to, and each collection's id, name,
  `schemaVersion` and count. Local-only fields, sync state and every key stay out: the AEK, the Secret Key, wrapped
  keys, record DEKs, and the identity in the keyring. Neither kind of file is a way into the account. A blob's DEK goes
  in only as part of its reference in a value: it opens that blob's copy on the server, whose bytes are in the file.
- **A sealed backup opens only with its passcode.** A random key seals it, wrapped under the passcode with PBKDF2 at
  600,000 iterations (`wrapKey`). Each 1 MiB chunk is AES-GCM with an AAD naming the backup, the chunk's place and
  whether it's the last, so a chunk that was changed, dropped, moved, repeated, taken from another backup, or a file
  cut short at a chunk's end, fails to open.
- **Nothing written from a file that doesn't check out.** Import reads the whole file before it writes: for a backup,
  every chunk; then the ZIP's checksums, every record, each collection's count against the manifest, and every blob's
  size against its reference.
- **Import keeps what this device holds.** A record this device holds with another value is kept unless the app asks
  for `replace`.

### 9.2 What they rely on

- **Where the file goes.** A plain export is unencrypted plaintext, wherever the browser saves it: a downloads folder,
  a synced drive, an email. The app says so where the user saves it.
- **The passcode.** A backup in cloud storage is open to offline guessing, slowed only by PBKDF2. The passcode rules
  are the app's.
- **A sync before the import.** What import adds is a pending change, and the next sync merges it with the server's
  copy by the collection's policy. Under `lastWriteWins` the import's value wins, so an old file imported on a device
  that hasn't pulled can replace a newer value from another device. After a sync the device holds the server's
  records, and import keeps them.
- **The file is the user's own.** A plain export carries no signature, so anyone who can change it can change what an
  import adds: import trusts its contents as the user's, as it would trust the user typing them in. `replace` widens
  that to records the device holds.

---

## 10. What the server learns

Sealing hides content, not the shape of the activity around it. A server that follows the contract still sees:

| It sees | Which tells it |
|---|---|
| The user id | Whose data it is |
| Collection ids | How many kinds of data the app keeps, though not what they are: ids are assigned, never names |
| Record ids | How many records each collection holds. Ids are random UUIDs, so they don't tell when a record was made |
| Ciphertext and blob sizes | Roughly how large each record and blob is. Nothing is padded |
| When each write, delete and pull happens | How active the user is, and when. `seq` orders writes; `deletedAt` and request times date them |
| Which records change together | Records pushed in one batch were probably edited together |
| The circle's devices | When devices join and are revoked, how many there are, and what their users call them (§4.4) |
| Channel membership | Who is in which channel, when invites happen, and the size and timing of what members write (§5.4) |
| The client's IP address and user agent | What the transport always shows |

It doesn't see the plaintext, field names, collection names, the AEK or any DEK, or the merge's clocks. No vector clock
travels in the clear, where it would count the user's devices and their edits: the clocks a merge needs travel inside
the ciphertext.

An app's privacy copy should state this list plainly rather than claim the server learns nothing.

---

## 11. What conseal doesn't protect against

### 11.1 Cross-site scripting (XSS)

**Threat:** injected JavaScript in the same origin can call `seal()`, `unseal()` and `loadCryptoKey()` directly, and use
the app's `CircleClient` and `SyncEngine`. Non-extractable `CryptoKey` objects can't have their bytes read, but the
attacker can still use them to encrypt, decrypt or sign anything, and can read what sits in the app's storage: the
Secret Key, synced records, the keyring.

**Why conseal can't fix this:** XSS breaks the browser's same-origin boundary. Once arbitrary JavaScript runs on your
page, it can use every API, conseal's included, as legitimately as your own code. This is an application-layer
problem, and the same goes for a device that is compromised while unlocked: it holds the AEK.

**Caller responsibility:** a strict [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP),
sanitised user-supplied HTML, and OWASP's XSS prevention guidelines. Don't run untrusted scripts in the same origin as
the encrypted data.

### 11.2 A compromised server that serves the code

**Threat:** an attacker who controls the server can also control the page the user loads, and serve JavaScript that
logs the passphrase before wrapping, or sends the AEK away.

**Why conseal can't fix this:** conseal wraps keys on the client, but if the attacker controls how the page is
delivered they can serve modified JavaScript. This is the classic way a server compromise breaks client-side crypto.

**Caller responsibility:** Subresource Integrity (SRI) for every script, a platform with tamper-evident deployments,
and monitoring for unexpected changes to the JavaScript you serve. Serving the app from somewhere other than the sync
server narrows who can do this.

### 11.3 Side channels

**Threat:** timing, cache-timing, power analysis or electromagnetic attacks on the cryptographic operations.

**Why conseal can't fix this:** these attacks target the hardware or the browser's `SubtleCrypto` implementation.
conseal has no influence over CPU caches, OS schedulers or physical hardware. Mitigating Spectre-class attacks is the
browser vendors' and the OS's job.

**Caller responsibility:** if your threat model includes nation-state physical access, conseal isn't the layer to
address it.

### 11.4 Keys in JavaScript memory

**Threat:** key material that passes through JavaScript, such as the passphrase string or raw bytes during wrapping,
may stay in memory where a memory-scanning attacker finds it.

**What conseal does:** the AEK and wrapped keys stay native `CryptoKey` objects wherever possible. Raw bytes exist only
briefly, during wrapping and unwrapping.

**What it can't do:** JavaScript has no manual memory management. Strings and `Uint8Array`s can't be zeroed; the
garbage collector decides when memory is freed.

### 11.5 Weak passphrases

**Threat:** a passphrase from a small dictionary ("123456", "password") shrinks the key space, whatever the iteration
count. The same holds for a sealed backup's passcode.

**conseal's position:** passphrase quality is the app's policy. conseal doesn't measure entropy.

**Caller responsibility:** enforce a minimum length and strength, or use `generateSecretKey()`, which makes the
iteration count irrelevant to a server's brute force.

### 11.6 Losing the Secret Key and the mnemonic

**Threat:** if the Secret Key is lost (the device destroyed, storage cleared, no backup) and the user hasn't kept their
mnemonic, the AEK can't be recovered, and everything sealed under it is gone for good.

**This is by design.** The server can't recover the AEK on the user's behalf; that is what zero knowledge means.

**Caller responsibility:** clear UX that has users keep their mnemonic and Secret Key before anything destructive, and
a recovery step during setup.

### 11.7 Exposing the mnemonic

**Threat:** the 24 words are a complete export of the AEK. Whoever has them can rebuild the AEK and open everything.

**conseal's position:** the mnemonic is for offline backup: on paper, or in a password manager. It should never travel
unencrypted or show without the user asking.

**Caller responsibility:** show it only on request, have the user acknowledge what it is, and never log it or send it
to a server.

---

## 12. Caller assumptions

The properties in this document hold **only if** these are true:

| # | Assumption | If it isn't |
|---|---|---|
| 1 | The app is served over **HTTPS** with a valid certificate | A network attacker can serve a malicious JavaScript bundle |
| 2 | The app enforces a **strict Content Security Policy**, with no inline scripts or untrusted sources | XSS can call conseal directly and use every key in IndexedDB |
| 3 | **Passphrases** have enough entropy, or a Secret Key is always used | Offline brute force against a stolen wrapped key becomes feasible |
| 4 | The **Secret Key** is never stored on the server or anywhere it can read | The defence against a compromised server (§3.1) collapses |
| 5 | The **mnemonic** is treated as a top secret, kept offline | One leak rebuilds the AEK |
| 6 | The app doesn't **eval** or run untrusted scripts in its origin | As 2: any script can use the loaded `CryptoKey`s |
| 7 | The browser's `SubtleCrypto` is **not compromised** | Every operation is the browser's; a backdoored browser breaks everything |
| 8 | `init()` runs before any `seal()` or `unseal()` that uses the stored AEK | `loadCryptoKey(AEK_KEY_ID)` returns `null`, and sealing throws on it. There is no fallback key |
| 9 | The app shows the **verification code** and approves a join only once the user confirms it matches | A server can swap the joining device's key and receive the AEK (§4.5) |
| 10 | An app that runs the circle without `CircleClient` takes the **commitment before the key pair**, derives the approving device's code from **its own commitment**, and **finishes a join only once the codes are confirmed** | A server can answer a join itself and read everything the device seals (§4.3) |
| 11 | Collections where a stale value matters use a **merge policy that compares versions** | A dishonest server can roll records back unnoticed (§6.3) |

---

## 13. Out of scope

These are deliberately outside conseal:

- **Transport security.** Use HTTPS.
- **Authentication.** Use a sign-in of your own: passwords, WebAuthn, OAuth. Sync takes the host app's.
- **Access control.** Decide who may call your API before data reaches conseal.
- **Availability.** A server can refuse service at any point: denial of service, withheld records, refused joins.
- **Revoked devices.** Revoking stops a device syncing but doesn't take back the AEK it held, or the identity in the
  keyring. That needs AEK rotation, and a new identity, which this version doesn't define.
- **Post-quantum cryptography.** None of the algorithms are yet mandated for browsers; conseal will revisit when
  `SubtleCrypto` adds them.
- **Obfuscation.** conseal doesn't hide that data is encrypted.
- **Anonymity.** conseal doesn't hide who communicates with whom (§10).

---

## 14. Reporting security issues

Follow the [responsible disclosure process](SECURITY.md) rather than opening a public issue. Encryption bugs get the
highest priority.
