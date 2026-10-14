# seal / unseal / generateAesKey / importAesKey

AES-256-GCM symmetric encryption. Use this to encrypt files and data with an AEK (Account Encryption Key) or a per-file DEK.

## Signatures

```ts
seal(key: CryptoKey, plaintext: ArrayBuffer, additionalData?: ArrayBuffer | Uint8Array): Promise<{ ciphertext: ArrayBuffer, iv: Uint8Array }>
unseal(key: CryptoKey, ciphertext: ArrayBuffer, iv: Uint8Array, additionalData?: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>
generateAesKey(extractable?: boolean): Promise<CryptoKey>
importAesKey(raw: ArrayBuffer | Uint8Array, extractable?: boolean): Promise<CryptoKey>
```

## Example

```ts
import { seal, unseal } from '@consealdev/conseal'

const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
)

// Encrypt a file
const file = document.querySelector('input[type=file]').files[0]
const plaintext = await file.arrayBuffer()
const { ciphertext, iv } = await seal(key, plaintext)
// Store ciphertext + iv — the iv is not secret but must be stored alongside ciphertext

// Decrypt
const plaintext2 = await unseal(key, ciphertext, iv)
const blob = new Blob([plaintext2], { type: file.type })
```

## Notes

- A fresh random IV is generated per `seal()` call — never reuse an IV with the same key.
- The authentication tag (last 16 bytes of ciphertext) is verified automatically on `unseal()`. Any tampering throws.
- `File` objects: call `await file.arrayBuffer()` to get an `ArrayBuffer` before passing to `seal()`.
- `unseal()` validates that the IV is exactly 12 bytes and throws a `TypeError` if not.
- `additionalData` (AAD) is authenticated but not encrypted: pass the same bytes to `unseal()`, or it throws. Use it to bind a ciphertext to its context, such as a record id.
- `generateAesKey()` and `importAesKey()` return non-extractable keys unless `extractable` is `true`, which `wrapKey` needs.
