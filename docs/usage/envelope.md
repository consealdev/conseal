# sealEnvelope / unsealEnvelope

Passcode-protected envelope encryption for recipients without a Conseal account.

## Signatures

```ts
sealEnvelope(plaintext: ArrayBuffer, passcode: string): Promise<SealedEnvelope>
unsealEnvelope(envelope: SealedEnvelope, passcode: string): Promise<ArrayBuffer>
encodeEnvelope(envelope: SealedEnvelope): string
decodeEnvelope(json: string): SealedEnvelope

interface SealedEnvelope {
  version: 1
  ciphertext: ArrayBuffer
  iv: Uint8Array
  wrappedKey: ArrayBuffer
  salt: Uint8Array
}
```

## Example

```ts
import { sealEnvelope, unsealEnvelope, encodeEnvelope, decodeEnvelope } from '@consealdev/conseal'

// Sender: seal the file and upload the result to the server
const plaintext = await file.arrayBuffer()
const envelope = await sealEnvelope(plaintext, 'tiger-moon-7')
const json = encodeEnvelope(envelope)
// POST json → server returns a link id
// Sender shares:
//   Link  → via email/message (comes from sender's own address)
//   Passcode 'tiger-moon-7' → via separate channel (SMS, phone call)

// Recipient: open the link, enter the passcode, decrypt in browser
const json = await fetch(`/d/${linkId}`).then(r => r.text())
const envelope = decodeEnvelope(json)
const result = await unsealEnvelope(envelope, 'tiger-moon-7')
const blob = new Blob([result])
```

## Notes

- The server stores the encoded envelope JSON — useless without the passcode.
- The passcode must travel via a different channel than the link (two-channel delivery).
- `sealEnvelope()` takes ~500ms due to PBKDF2 — show a loading indicator.
- Throws if the passcode is wrong.
