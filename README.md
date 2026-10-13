<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/consealdev/conseal/main/docs/assets/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/consealdev/conseal/main/docs/assets/logo-light.svg" style="width: 4rem; height: 4rem;" alt="Conseal logo">
  </picture>
</p>

<h1 align="center">Conseal</h1>

<p align="center">
  Zero-knowledge cryptography and private communication.
</p>

---

## Install

```bash
npm install @consealdev/conseal
```

## Quick start

```ts
import { seal, unseal, generateAesKey } from '@consealdev/conseal'

// Generate a key and encrypt
const key = await generateAesKey()
const plaintext = await file.arrayBuffer()
const { ciphertext, iv } = await seal(key, plaintext)

// Decrypt
const result = await unseal(key, ciphertext, iv)
```

## API

### Symmetric encryption (AES-256-GCM)

| Function | Description |
|---|---|
| `seal(key, plaintext, additionalData?)` | Encrypts with a random 96-bit IV. Returns `{ ciphertext, iv }`. |
| `unseal(key, ciphertext, iv, additionalData?)` | Decrypts. Throws on tampered data or AAD mismatch. |
| `generateAesKey(extractable?)` | Generates a random AES-256 key. |
| `importAesKey(raw, extractable?)` | Imports raw key bytes as a CryptoKey. |

### Passphrase key wrapping (PBKDF2 + AES-KW)

| Function | Description |
|---|---|
| `wrapKey(passphrase, key)` | Wraps a CryptoKey with a passphrase. Returns `{ wrappedKey, salt }`. |
| `unwrapKey(passphrase, wrappedKey, salt)` | Unwraps. Throws on wrong passphrase. |
| `rekey(oldPass, newPass, wrappedKey, salt)` | Changes passphrase without re-encrypting data. |

### Asymmetric encryption (ECDH P-256)

| Function | Description |
|---|---|
| `sealMessage(recipientPublicKey, plaintext)` | Encrypts for a recipient using ephemeral ECDH. |
| `unsealMessage(privateKey, ciphertext, iv, ephemeralPublicKey)` | Decrypts with the recipient's private key. |
| `generateECDHKeyPair()` | Generates a P-256 ECDH key pair. |

### Digital signatures (ECDSA P-256)

| Function | Description |
|---|---|
| `sign(privateKey, data)` | Signs data with ECDSA-SHA256. |
| `verify(publicKey, signature, data)` | Verifies a signature. Returns `true` or `false`. |
| `generateECDSAKeyPair()` | Generates a P-256 ECDSA key pair. |

### Envelope encryption (passcode-protected)

| Function | Description |
|---|---|
| `sealEnvelope(plaintext, passcode)` | Encrypts for a recipient without a Conseal account. |
| `unsealEnvelope(envelope, passcode)` | Decrypts with the passcode. |
| `encodeEnvelope(envelope)` | Serialises a `SealedEnvelope` to JSON. |
| `decodeEnvelope(json)` | Deserialises JSON back to a `SealedEnvelope`. |

### Multi-device private communication (Circle)

Establishes a bounded group of trusted devices that all hold the same Account Encryption Key (AEK). The mnemonic is the root of trust — the AEK is always derived from it, so any device can recover the AEK from the mnemonic alone if the passphrase or wrapped key is lost.

Account creation flow:

```ts
const mnemonic = generateMnemonic()          // show to user — write it down, never store it
const { wrappedAEK, aekCommitment, deviceId } = await initCircle(mnemonic, passphrase, secretKey)
// store wrappedAEK + aekCommitment server-side
```

Recovery flow (lost passphrase or wrapped key):

```ts
const aek = await recoverWithMnemonic(mnemonic, true)  // re-derive AEK from mnemonic
const { wrappedKey, salt } = await wrapKey(newPassphrase, aek, newSecretKey)
// upload new wrappedKey to server
```

Four functions cover the full device-registration ceremony:

| Function | Description |
|---|---|
| `initCircle(mnemonic, passphrase, secretKey)` | Founding device derives the shared AEK from the mnemonic, wraps it, and returns `wrappedAEK`, `aekCommitment`, and `deviceId`. |
| `createJoinRequest(deviceMeta?)` | New device generates an ephemeral ECDH key pair. Returns the join request payload, the ephemeral private key (memory-only), and a `verificationCode` to display to the user. |
| `authorizeJoin(joinRequest, wrappedAEK, passphrase, secretKey)` | Trusted device unwraps its AEK and seals it for the new device via ECDH. Rejects requests older than 5 minutes. |
| `finalizeJoin(sealedAEK, ephemeralPrivateKey, passphrase, secretKey, aekCommitment)` | New device unseals the AEK, verifies the commitment, and re-wraps it under its own credentials. Throws on commitment mismatch. |
| `deriveVerificationCode(ephemeralPublicKey)` | Derives a `XX-XX-XX` hex code from a public key. Both devices must show matching codes before approval to prevent MITM. |

### Device initialisation

| Function | Description |
|---|---|
| `init(wrappedKey, salt, passphrase)` | Unwraps the AEK and stores it in IndexedDB. |
| `AEK_KEY_ID` | The IndexedDB key id for the AEK (`'aek'`). |

### Mnemonic recovery (BIP-39)

| Function | Description |
|---|---|
| `generateMnemonic()` | Generates a 24-word recovery phrase (256 bits of entropy). |
| `recoverWithMnemonic(mnemonic, extractable?)` | Derives the AEK from the mnemonic. Pass `extractable: true` when passing to `initCircle` or `wrapKey`. |

### Key serialisation (JWK)

| Function | Description |
|---|---|
| `exportPublicKeyAsJwk(key)` | Exports a public CryptoKey to JWK. |
| `importPublicKeyFromJwk(jwk, algorithm)` | Imports a JWK as a CryptoKey (`'ECDH'` or `'ECDSA'`). |

### IndexedDB key storage

```ts
import { saveCryptoKey, loadCryptoKey, deleteCryptoKey } from '@consealdev/conseal'
```

| Function | Description |
|---|---|
| `saveCryptoKey(name, key)` | Persists a CryptoKey to IndexedDB. |
| `loadCryptoKey(name)` | Loads a CryptoKey. Returns `null` if not found. |
| `deleteCryptoKey(name)` | Deletes a CryptoKey. |

### Utilities

| Function | Description |
|---|---|
| `toBase64(buf)` / `fromBase64(b64)` | Standard base64 encoding/decoding. |
| `toBase64Url(buf)` / `fromBase64Url(b64)` | URL-safe base64 (no padding). |
| `digest(data)` | SHA-256 hash. |

## Design

- **Zero runtime secrets on the server.** All encryption and decryption happens in the browser. The server stores only wrapped keys and ciphertext.
- **SubtleCrypto everywhere.** No OpenSSL, no polyfills, no WASM. The only runtime dependency is [`@scure/bip39`](https://github.com/nicolo-ribaudo/noble-bip39) for mnemonic wordlists (bundled into the output).
- **Non-extractable keys.** Keys stored in IndexedDB have `extractable: false` — JavaScript cannot read the raw bytes, only use them for encrypt/decrypt.
- **PBKDF2 at 600,000 iterations.** Passphrase-derived keys use SHA-256 with a 128-bit random salt per wrap. Intentionally slow to resist offline brute-force.

## Requirements

- Browser with [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) support (all modern browsers)
- Node.js >= 18 (for testing / SSR with `globalThis.crypto`)

## Development

```bash
npm install
npm test           # unit tests (Vitest + happy-dom)
npm run build      # build to dist/
```

### Cross-browser tests

SubtleCrypto behaviour is not identical across engines. The browser suite runs the full test suite in real Chromium, Firefox, and WebKit engines via Playwright.

First-time setup — download browser binaries (~300 MB, one-off):

```bash
npx playwright install
```

Then run:

```bash
npm run test:browser
```

WebKit is the highest-value target: every browser on iOS uses WebKit under the hood regardless of brand, so this provides real Safari/iOS coverage without a device.

Both suites run automatically on CI for every push and pull request to `main`.

## License

Dual-licensed under [AGPL-3.0](LICENSE) and a [commercial license](COMMERCIAL-LICENSE.md).
