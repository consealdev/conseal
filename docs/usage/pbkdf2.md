# wrapKey / unwrapKey / rekey / rekeySecretKey

PBKDF2-SHA256 key derivation and AES-KW key wrapping. Use this to protect an AEK with a user passphrase, optionally hardened with a [Secret Key](./secret-key.md).

## Signatures

```ts
wrapKey(passphrase: string, key: CryptoKey, secretKey?: Uint8Array): Promise<{ wrappedKey: ArrayBuffer, salt: Uint8Array }>
unwrapKey(passphrase: string, wrappedKey: ArrayBuffer, salt: Uint8Array, secretKey?: Uint8Array): Promise<CryptoKey>
rekey(oldPassphrase: string, newPassphrase: string, wrappedKey: ArrayBuffer, salt: Uint8Array, secretKey?: Uint8Array): Promise<{ wrappedKey: ArrayBuffer, salt: Uint8Array }>
rekeySecretKey(passphrase: string, oldSecretKey: Uint8Array, newSecretKey: Uint8Array, wrappedKey: ArrayBuffer, salt: Uint8Array): Promise<{ wrappedKey: ArrayBuffer, salt: Uint8Array }>
```

## Example: account setup

```ts
import { wrapKey, unwrapKey, rekey } from '@consealdev/conseal'

// Account setup: generate AEK, wrap with passphrase, store wrapped key + salt on server
const aek = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
)
const { wrappedKey, salt } = await wrapKey('my-strong-passphrase', aek)
// POST { wrappedKey: btoa(...), salt: btoa(...) } to server

// New device: fetch wrappedKey + salt, unwrap with passphrase
const recovered = await unwrapKey('my-strong-passphrase', wrappedKey, salt)

// Passphrase change — no files need re-encryption
const { wrappedKey: newWrapped, salt: newSalt } = await rekey('old-pass', 'new-pass', wrappedKey, salt)
```

## Example: with Secret Key (recommended)

```ts
import { generateSecretKey, wrapKey, unwrapKey, rekey, rekeySecretKey } from '@consealdev/conseal'

const sk = generateSecretKey()
// store sk in localStorage and keep an offline copy

const aek = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
)
const { wrappedKey, salt } = await wrapKey('my-passphrase', aek, sk)
const recovered = await unwrapKey('my-passphrase', wrappedKey, salt, sk)

// Passphrase change — Secret Key stays the same
const { wrappedKey: newWrapped, salt: newSalt } = await rekey('old-pass', 'new-pass', wrappedKey, salt, sk)

// Secret Key rotation (compromise event only) — passphrase stays the same
const newSk = generateSecretKey()
const { wrappedKey: rotated, salt: rotatedSalt } = await rekeySecretKey('my-passphrase', sk, newSk, wrappedKey, salt)
```

## Notes

- `wrapKey()` requires the key to have `extractable: true`. Throws if `key.extractable` is false.
- `unwrapKey()` always returns `extractable: false` — safe for IndexedDB storage.
- PBKDF2 at 600,000 iterations takes ~200–500ms — this is intentional offline brute-force protection.
- The `salt` is not secret. Store it alongside `wrappedKey`.
- When a `secretKey` is provided, it is combined with the passphrase via SHA-256 before PBKDF2 runs. An attacker who steals `wrappedKey` and `salt` cannot brute-force without also knowing the Secret Key.
- `rekeySecretKey` is a rare, heavyweight operation — use it only when the Secret Key is compromised. It requires re-enrolling all devices.
