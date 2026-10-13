# digest

SHA-256 hash function. Use this for key fingerprinting, content hashing, and integrity checks.

## Signature

```ts
digest(data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>
```

## Example

```ts
import { digest, toBase64 } from '@consealdev/conseal'

const data = new TextEncoder().encode('hello world')
const hash = await digest(data)
console.log(toBase64(hash)) // SHA-256 hash as base64 string
```

## Notes

- Returns a 32-byte (256-bit) `ArrayBuffer`.
- Deterministic — same input always produces the same hash.
- Accepts both `ArrayBuffer` and `Uint8Array`.
