# generateECDSAKeyPair / sign / verify

ECDSA P-256 signing for sender verification.

## Signatures

```ts
generateECDSAKeyPair(): Promise<CryptoKeyPair>
sign(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>
verify(publicKey: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>
```

## Example

```ts
import { generateECDSAKeyPair, sign, verify } from '@consealdev/conseal'

// One-time: generate key pair
const { publicKey, privateKey } = await generateECDSAKeyPair()

// Sender: sign the ciphertext before sending
const signature = await sign(privateKey, ciphertext)
// POST { ciphertext, iv, signature } to server

// Recipient: verify using sender's registered public key
const valid = await verify(senderPublicKey, signature, ciphertext)
if (!valid) throw new Error('Signature verification failed')
```

## Notes

- Sign the ciphertext, not the plaintext — the recipient verifies before decrypting.
- `verify()` returns `false` for invalid signatures rather than throwing.
