# generateECDHKeyPair / sealMessage / unsealMessage

ECDH P-256 asymmetric encryption for account-to-account file and message delivery.

## Signatures

```ts
generateECDHKeyPair(): Promise<CryptoKeyPair>
sealMessage(recipientPublicKey: CryptoKey, plaintext: ArrayBuffer): Promise<{ ciphertext: ArrayBuffer, iv: Uint8Array, ephemeralPublicKey: JsonWebKey }>
unsealMessage(recipientPrivateKey: CryptoKey, ciphertext: ArrayBuffer, iv: Uint8Array, ephemeralPublicKey: JsonWebKey): Promise<ArrayBuffer>
```

## Example

```ts
import { generateECDHKeyPair, sealMessage, unsealMessage, exportPublicKeyAsJwk, importPublicKeyFromJwk } from '@consealdev/conseal'

// One-time: generate key pair, register public key with server
const { publicKey, privateKey } = await generateECDHKeyPair()
const jwk = await exportPublicKeyAsJwk(publicKey)
// PUT /keys/me { jwk }

// Sender: fetch recipient's public key, encrypt
const recipientJwk = await fetch('/keys/alice').then(r => r.json())
const recipientKey = await importPublicKeyFromJwk(recipientJwk, 'ECDH')
const plaintext = await file.arrayBuffer()
const { ciphertext, iv, ephemeralPublicKey } = await sealMessage(recipientKey, plaintext)
// POST { ciphertext, iv, ephemeralPublicKey } to server

// Recipient: decrypt
const result = await unsealMessage(privateKey, ciphertext, iv, ephemeralPublicKey)
```

## Notes

- A fresh ephemeral key pair is generated per `sealMessage()` call. The ephemeral private key is never returned or stored.
- Store `{ ciphertext, iv, ephemeralPublicKey }` together — all three are required to decrypt.
