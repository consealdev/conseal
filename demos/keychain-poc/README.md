# Keychain PoC — Mixed-Principal End-to-End Encryption

Proves the core claim from `Conseal-next.md`:

> A human authorizes a scope, a service joins it, the service encrypts data for
> the human, the human decrypts it — and a relay in the middle holds only
> ciphertext at every step.

No new library code. Four scripts using the existing `conseal` API, one dumb relay
server. No Rust, no cross-language bindings — the protocol claim does not depend on
those.

---

## What gets proven

| Step | Claim |
|---|---|
| Human creates scope, posts sealed invitation | Relay stores sealed key material it cannot open |
| Service claims invitation, recovers AEK | Circle ceremony works for a non-device principal |
| Service posts reply encrypted with human's ECDH public key | Service-to-human confidential delivery works |
| Human decrypts the reply | Human's private key is the only path to plaintext |
| Relay log shows only base64 blobs throughout | Relay is structurally excluded — not by policy |

---

## Files

```
demos/keychain-poc/
    README.md               ← you are here
    relay.js                ← dumb HTTP store, no crypto, logs every blob it receives
    1-human-init.js         ← human: creates scope (AEK + mnemonic), posts scope manifest
    2-service-join.js       ← service: creates join request, posts to relay, prints verification code
    3-human-authorize.js    ← human: fetches join request, verifies code, seals AEK for service
    4-service-finalize.js   ← service: finalizes join, recovers AEK, posts encrypted reply
    5-human-read.js         ← human: fetches encrypted reply, decrypts it, prints plaintext
```

The ceremony requires two rounds of relay interaction (service posts request → human
authorizes → service finalizes), which is why there are five scripts. State that must
stay private (passphrases, secret keys, private keys) is written to local JSON files
and never sent to the relay. The relay never receives a passphrase, a key, or plaintext.

---

## Prerequisites

```
node >= 18
```

No extra dependencies. The relay uses the built-in `node:http` module. The client
scripts import from the built `conseal` package.

Build the library first:

```bash
# from the repo root
npm install
npm run build
```

---

## Running

Open two terminals from the repo root.

**Terminal 1 — start the relay**

```bash
node demos/keychain-poc/relay.js
```

Output:
```
Relay listening on http://localhost:4400
This server is a structural relay — it stores blobs and cannot read them.
```

Leave this running. Every blob it receives is logged. You will see only
base64-encoded blobs — never a passphrase, never plaintext.

**Terminal 2 — run the five steps in sequence**

**Step 1: Human initialises the scope**

```bash
node demos/keychain-poc/1-human-init.js
```

What it does:
1. Generates a BIP-39 mnemonic (the scope's root of trust).
2. Calls `initCircle` to derive the AEK and wrap it under a passphrase + secret key.
3. Generates a long-term ECDH key pair (so the service can send the human encrypted replies).
4. Posts the scope manifest (aekCommitment + ECDH public key) to the relay.
5. Writes `human-state.json` — mnemonic, passphrase, secret key, wrapped AEK, ECDH private key.
   **This file never reaches the relay.**

Output:
```
[human] mnemonic: abandon ability able ...
[human] scope initialised  deviceId: <uuid>
[human] scope manifest posted to relay (aekCommitment + ECDH public key)
[human] private state saved to human-state.json
```

**Step 2: Service creates a join request**

```bash
node demos/keychain-poc/2-service-join.js
```

What it does:
1. Calls `createJoinRequest` to generate an ephemeral ECDH key pair for the ceremony.
2. Posts the join request to the relay with a server-stamped arrival time.
3. Writes `service-state.json` — ephemeral private key and service credentials.

Output:
```
[service] verification code: A3-4F-9C-12   ← note this
[service] join request posted to relay
[service] state saved to service-state.json
```

**Step 3: Human authorizes the service**

```bash
node demos/keychain-poc/3-human-authorize.js
```

What it does:
1. Loads `human-state.json`.
2. Fetches the join request from the relay.
3. Derives the verification code from the service's ephemeral public key and prints it.
4. Calls `authorizeJoin` to seal the AEK specifically for the service's ephemeral key.
5. Posts the sealed AEK and commitment to the relay.

Output:
```
[human] verification code: A3-4F-9C-12   ← must match step 2
[human] AEK sealed for service
[human] sealed AEK posted to relay
```

> **Verification code check**: both sides derive the same code from the service's
> ephemeral public key. A mismatch means the join request was tampered with in transit.
> In this PoC, compare them visually. A real UI would require an explicit confirmation step.

**Step 4: Service finalizes join and sends encrypted reply**

```bash
node demos/keychain-poc/4-service-finalize.js
```

What it does:
1. Fetches the sealed AEK from the relay.
2. Calls `finalizeJoin` to recover the AEK via ECDH and verify the commitment (tamper check).
3. Re-wraps the AEK under the service's own credentials.
4. Fetches the human's ECDH public key from the relay.
5. Calls `sealMessage` to encrypt a reply specifically for the human's public key.
6. Posts the encrypted reply to the relay.

Output:
```
[service] AEK recovered and commitment verified ✓  (tamper check passed)
[service] AEK re-wrapped under service credentials
[service] encrypted reply posted to relay
[service] plaintext (only human can read): "Hello from the analytics service..."
```

**Step 5: Human reads the reply**

```bash
node demos/keychain-poc/5-human-read.js
```

What it does:
1. Loads `human-state.json`.
2. Fetches the encrypted reply from the relay.
3. Decrypts using the human's ECDH private key.
4. Prints the plaintext and a proof summary.

Output:
```
[human] fetched encrypted reply from relay
[human] decrypted reply:
  "Hello from the analytics service. The relay never saw this message."

--- Proof summary ---
✓ Human created a scope. Service joined via the circle ceremony.
✓ Service encrypted a message for the human's ECDH public key.
✓ Human decrypted it using only their local private key.
✓ The relay held every blob in this exchange and could read none of it.
```

---

## What the relay log shows

After the full run the relay will have logged something like:

```
[relay] POST /store/scope-manifest    — 182 bytes stored (relay cannot read this)
[relay] POST /store/join-request      — 334 bytes stored (relay cannot read this)
[relay] POST /store/sealed-aek        — 521 bytes stored (relay cannot read this)
[relay] POST /store/service-reply     — 298 bytes stored (relay cannot read this)
```

No passphrase. No AEK bytes. No plaintext. Four blobs in, zero plaintext out.

---

## What this PoC does not cover

| Out of scope | Reason |
|---|---|
| Cross-language interop | Needs Rust core; protocol claim proven here without it |
| Multiple scopes | Set a different `SCOPE_ID` prefix per run; trivial extension |
| Revocation | Re-key the scope: `initCircle` again, re-authorize remaining principals |
| Production key storage | Service writes to a local JSON file here; production uses KMS/HSM |

---

## Extending to multiple scopes

Set a different scope identifier before each run:

```bash
SCOPE_ID=health/general node demos/keychain-poc/1-human-init.js
SCOPE_ID=health/general node demos/keychain-poc/2-service-join.js
SCOPE_ID=health/general node demos/keychain-poc/3-human-read.js
```

Each scope produces an independent AEK and circle. A service authorized to
`analytics` cannot decrypt data from `health/general`. The relay stores blobs for
all scopes — it cannot distinguish them.
