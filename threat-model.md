# Conseal — Threat Model

> **Version:** April 2026  
> **Scope:** `conseal` library v0.x – v1.x  
> **Audience:** Integrators, security reviewers, and auditors.

---

## 1. Purpose

This document defines:

- What **threat actors** conseal is designed to resist.
- What **property** each defence provides.
- What conseal **explicitly does not protect against** — and why.
- What **assumptions callers must satisfy** for the security properties to hold.

---

## 2. System Summary

Conseal is a browser-side cryptography library built entirely on the [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/) (`SubtleCrypto`). Its central promise is **zero-knowledge architecture**: the server stores only ciphertext and wrapped keys — never plaintext and never bare key material. All cryptographic operations occur inside the browser.

### Key assets

| Asset | Description | Where it lives |
|---|---|---|
| **AEK** (Account Encryption Key) | Root AES-256-GCM key; all user data is encrypted with it | IndexedDB (non-extractable `CryptoKey`) |
| **Wrapped AEK** | AEK protected by PBKDF2 + AES-GCM | Server / cloud storage |
| **Secret Key (SK)** | 128-bit second factor for AEK wrapping | Device-local storage (e.g. `localStorage`) |
| **Passphrase** | Human-chosen credential; combined with SK into PBKDF2 | User's memory only |
| **Plaintext** | Application data before encryption | Exists only transiently in JavaScript memory |
| **Ciphertext** | AES-256-GCM encrypted application data | Server / cloud storage |
| **ECDH / ECDSA key pairs** | Per-user asymmetric keys for messaging and signing | Server (public key) / IndexedDB (private key) |
| **BIP-39 mnemonic** | 24-word phrase the AEK is derived from, kept as an offline backup | User's written record only |
| **Channel AEK** | AES-256-GCM key shared by a channel's members, across users | Members' devices, as a non-extractable `CryptoKey` |
| **Wrapped channel AEK** | Channel AEK under one member's circle AEK (AES-GCM, bound to the channel id) | Server, one per member |

---

## 3. Threat Actors

### 3.1 Malicious or compromised server

**Capability:** Full access to the database — ciphertext, wrapped keys, salts, public keys.

**What the attacker gains:**
- Ciphertext blobs — useless without the AEK.
- Wrapped AEK + salt — useless without the passphrase and (if used) the Secret Key.
- ECDH / ECDSA public keys — non-sensitive by design.
- No access to the plaintext AEK, the Secret Key, or the passphrase.

**Conseal's defence:** PBKDF2 with 600,000 HMAC-SHA-256 iterations makes offline passphrase guessing expensive. Combined with a 128-bit Secret Key (which never reaches the server), the server cannot brute-force the wrapping key even with indefinite compute time.

**Residual risk:** A weak passphrase without a Secret Key reduces to the strength of that passphrase alone. Callers should enforce minimum passphrase strength or mandate Secret Key use.

---

### 3.2 Network attacker (passive or active MitM)

**Capability:** Observe and/or modify HTTP traffic.

**What the attacker gains with TLS:**
- Nothing useful — all transmitted data is ciphertext or wrapped keys.

**What the attacker gains without TLS:**
- Could substitute a malicious JavaScript bundle, defeating all security properties.

**Conseal's defence:** Not in scope — conseal does not manage transport. callers **must** serve their application over HTTPS.

---

### 3.3 Offline brute-force against a stolen wrapped key

**Capability:** Offline dictionary or brute-force attack on a `{ wrappedKey, salt }` pair retrieved from the server or a backup.

**Conseal's defence:**
- PBKDF2 at 600,000 iterations ≈ 200–500 ms per guess on modern hardware.
- A 128-bit random Secret Key raises the effective key space to 2¹²⁸ · |passphrase space|, making exhaustive search infeasible even with specialised hardware.
- Each salt is randomly generated per wrap, so pre-computation (rainbow table) attacks do not apply.

---

### 3.4 Passive logging or key escrow by the library

**Capability:** Concern that conseal silently exfiltrates key material.

**Conseal's defence:** The library is open-source and auditable. It makes no network requests. Key material is passed only to `SubtleCrypto`, which enforces `extractable: false` on stored keys — preventing JavaScript code (including conseal itself) from reading raw key bytes out of IndexedDB.

---

### 3.5 Tampering with ciphertext in transit or storage

**Capability:** Flip bits in a stored or transmitted ciphertext.

**Conseal's defence:** AES-256-GCM is an authenticated encryption scheme. Any modification to the ciphertext, the IV, or the AAD (if used) causes `unseal()` / `unsealMessage()` / `unsealEnvelope()` to throw a `DOMException` — the tampered bytes are never returned to the caller. There is no "decrypt-and-ignore-the-tag" path.

---

## 4. What Conseal Does NOT Protect Against

### 4.1 Cross-Site Scripting (XSS)

**Threat:** Injected JavaScript in the same origin can call `conseal.seal()`, `conseal.unseal()`, and `loadCryptoKey()` directly. Non-extractable `CryptoKey` objects cannot have their bytes read, but the attacker can still use them to encrypt, decrypt, or sign arbitrary data.

**Why conseal cannot fix this:** XSS breaks the browser's same-origin security boundary. Once arbitrary JavaScript executes on your page, it can use every API — including conseal's — as legitimately as your own code. This is an application-layer problem.

**Caller responsibility:** Implement a strict [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), sanitise all user-supplied HTML, and follow OWASP XSS prevention guidelines. Do not execute untrusted scripts in the same origin as the encrypted data.

---

### 4.2 Server Compromise with Key Theft

**Threat:** An attacker who compromises the server and can also intercept the user's next login receives the wrapped AEK and then observes the passphrase (e.g. via a malicious API response that logs the passphrase before wrapping).

**Why conseal cannot fix this:** conseal wraps keys on the client, but if the attacker controls the page delivery they can serve modified JavaScript. This is the classic "server compromise breaks client-side crypto" problem.

**Caller responsibility:** Use Subresource Integrity (SRI) for all scripts, deploy to a platform with tamper-evident deployments, and consider a Security Policy. Monitor for unexpected changes to served JavaScript.

---

### 4.3 Side-Channel Attacks

**Threat:** Timing attacks, cache-timing, power analysis, or EM side-channels against the cryptographic operations.

**Why conseal cannot fix this:** These attacks target the hardware or the browser's `SubtleCrypto` implementation. conseal has no influence over CPU caches, OS schedulers, or physical hardware. Mitigating hardware side-channels (e.g. Spectre, Meltdown) is the responsibility of browser vendors and the OS.

**Caller responsibility:** If your threat model includes nation-state-level physical access, conseal is not the right layer to address it. Rely on the browser vendor's mitigations for Spectre-class attacks.

---

### 4.4 Key Leakage via JavaScript Memory

**Threat:** Key material that passes through JavaScript (e.g. the passphrase string, the raw bytes returned from `toBase64` helpers) may remain in memory and be accessible to a memory-scanning attacker.

**What conseal does:** AEK and wrapped keys are kept as native `CryptoKey` objects wherever possible. Raw bytes only exist transiently during wrapping/unwrapping.

**What conseal cannot do:** JavaScript does not have manual memory management. String and `Uint8Array` values cannot be zeroed; the garbage collector decides when memory is freed. A sufficiently powerful attacker who can scan the JS heap may find transient key bytes.

---

### 4.5 Weak Passphrases

**Threat:** A passphrase chosen from a small dictionary ("123456", "password") dramatically shrinks the effective key space regardless of iteration count.

**Conseal's position:** Passphrase quality is an application policy decision. conseal does not validate entropy.

**Caller responsibility:** Enforce minimum passphrase length and entropy, or use `generateSecretKey()` to make the iteration count irrelevant to server-side brute force.

---

### 4.6 Loss of the Secret Key

**Threat:** If the Secret Key is lost (device destroyed, `localStorage` cleared, no backup) and the user has not retained their BIP-39 mnemonic, the AEK cannot be recovered — all encrypted data is permanently inaccessible.

**This is by design.** Conseal enforces zero-knowledge by ensuring the server cannot recover the AEK on the user's behalf. Irrecoverability is the flip side of that guarantee.

**Caller responsibility:** Display clear UX prompting users to store their mnemonic and Secret Key before performing destructive operations. Consider offering a "recovery export" step during account setup.

---

### 4.7 BIP-39 Mnemonic Exposure

**Threat:** The 24-word mnemonic is a complete export of the AEK. Anyone who obtains it can reconstruct the AEK and decrypt all data.

**Conseal's position:** The mnemonic is intended for offline backup (written on paper, stored in a password manager). It should never be transmitted unencrypted or displayed without user intent.

**Caller responsibility:** Display the mnemonic only on user request, prompt the user to acknowledge its sensitivity, and never log it or transmit it to a server.

---

## 5. Caller Assumptions

The security properties documented here hold **only if** the following conditions are satisfied:

| # | Assumption | Consequence of violation |
|---|---|---|
| 1 | The application is served over **HTTPS** with a valid certificate | A network attacker can substitute a malicious JavaScript bundle |
| 2 | The application enforces a **strict Content Security Policy** preventing inline scripts and untrusted sources | XSS can call conseal APIs directly and access all IndexedDB keys |
| 3 | **Passphrases** are chosen with adequate entropy, or a Secret Key is always used | Offline brute-force against a stolen wrapped key becomes feasible |
| 4 | The **Secret Key** (if used) is not stored on the server or in any server-readable location | The server-compromise defence collapses |
| 5 | The **BIP-39 mnemonic** is treated as a high-secrets credential (offline storage only) | A single leak allows full AEK reconstruction |
| 6 | The application does not **eval** or execute untrusted scripts in the same origin | Equivalent to assumption 2; any arbitrary script can use loaded `CryptoKey` objects |
| 7 | The browser's `SubtleCrypto` implementation is **not compromised** | All cryptographic operations are delegated to the browser; a backdoored browser breaks everything |
| 8 | `init()` is called before any `seal()` / `unseal()` operation | `loadCryptoKey(AEK_KEY_ID)` returns `null`, and `seal()` / `unseal()` throw on it. There is no fallback key |

---

## 6. Cryptographic Algorithm Choices

| Primitive | Algorithm | Parameters | Justification |
|---|---|---|---|
| Symmetric encryption | AES-GCM | 256-bit key, 12-byte IV, 128-bit tag | NIST standard; authenticated; hardware-accelerated in all modern CPUs and browsers |
| Key derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations, 16-byte random salt | RFC 8018; NIST SP 800-132 recommendation ≥ 210,000 for SHA-256; broad browser support |
| Key wrapping | AES-GCM | 256-bit wrapping key from PBKDF2, 12-byte random IV prepended to the wrapped key, 128-bit tag | Authenticated on every engine, so a wrong passphrase or Secret Key throws. Not AES-KW: WebKit doesn't enforce its integrity check, so a wrong credential could return garbage instead of throwing |
| Key agreement | ECDH | NIST P-256 | Widely available in SubtleCrypto; adequate for the threat model; no dependencies |
| Signatures | ECDSA | NIST P-256, SHA-256 | Same rationale as ECDH; P-256 is the baseline curve in WebCrypto |
| Hashing | SHA-256 | — | Universal; used as PBKDF2 PRF and standalone digest |
| Mnemonic encoding | BIP-39 | 24 words (256-bit entropy + 8-bit checksum) | Human-writeable offline backup; well-specified; implemented by `@scure/bip39` |
| Mnemonic to AEK | HKDF-SHA-256 | Empty salt, info `conseal-mnemonic-aek-v1` | The entropy is already uniform; the label keeps this key apart from any other use of the same entropy |
| Randomness | `crypto.getRandomValues` | — | CSPRNG; provided by the browser/OS; no user-space RNG |

---

## 7. Out-of-Scope Items

The following are **deliberately outside conseal's scope**:

- **Transport security** — use HTTPS / TLS.
- **Authentication** — use a dedicated auth layer (passwords, WebAuthn, OAuth).
- **Access control** — decide who may call your API before passing data to conseal.
- **Post-quantum cryptography** — none of the required algorithms are yet mandated for browser use; conseal will revisit when `SubtleCrypto` adds post-quantum primitives.
- **Obfuscation** — conseal does not hide that data is encrypted.
- **Anonymity** — conseal does not hide who is communicating with whom.

---

## 8. Channels

A channel is a shared encrypted space across users: its members read and write with one random channel AEK. Each member holds it wrapped under their own circle AEK, so every device in their circle opens it. An invite runs the circle's join ceremony between two users.

### What the server holds

Per channel, the AEK commitment (SHA-256 of the channel AEK) and one wrapped copy per member. Per pending invite, the invitee's ephemeral public key and, once a member authorizes it, the channel AEK sealed to that key. None of it opens without a member's circle AEK or the invitee's ephemeral private key.

### What conseal enforces

- **Copies bound to their channel.** A wrapped copy carries the channel id in its AAD. The server can't serve one channel's copy as another's, or pass any other key the circle AEK wraps off as a channel AEK.
- **The commitment, at the invite.** The invitee checks the key it receives against the commitment it took before making its request. A mismatch throws, and nothing is stored.
- **A code that covers the commitment.** The invite's verification code is derived from the channel id, the commitment and the invitee's ephemeral public key, and the member's side computes the commitment from the key it holds. The request's public key is public, so a server that relays it can seal a key of its own to it and give the invitee a commitment to match; the two codes then differ. A swapped public key changes the member's code.
- **Fresh requests.** `authorizeChannelJoin` refuses a request the server received more than 5 minutes earlier.

### What it relies on

- **The code comparison, on both sides.** The member confirms the codes match before authorizing, the invitee before finalizing. Without the member's confirmation, the channel AEK can go to a key the server holds; without the invitee's, the invitee can accept a key the server chose.
- **The server's receipt time,** passed as `serverReceivedAt`, never a time the invitee supplied.
- **The backend, for membership.** Removing a member is access control: the server stops serving them the channel. They keep the channel AEK and everything they received while a member. A fresh key means a new channel and new invites.
- **Each member's circle.** A copy is as safe as the circle AEK it is wrapped under: whoever can use a member's circle AEK opens every channel the member is in.

### What the server still learns

Who is in which channel, when invites happen, and the size and timing of what members write. Channels hide content, not membership (§7, Anonymity).

---

## 9. Reporting Security Issues

Please follow the [responsible disclosure process](../SECURITY.md) rather than opening a public issue. Encryption bugs are treated with the highest priority.
