# toBase64 / fromBase64 / toBase64Url / fromBase64Url

Base64 encoding and decoding utilities for converting between binary data and text-safe strings.

## Signatures

```ts
toBase64(buf: ArrayBuffer | Uint8Array): string
fromBase64(b64: string): Uint8Array
toBase64Url(buf: ArrayBuffer | Uint8Array): string
fromBase64Url(b64url: string): Uint8Array
```

## Example

```ts
import { toBase64, fromBase64, toBase64Url, fromBase64Url } from '@consealdev/conseal'

// Standard base64 — for storage or text-based transmission
const encoded = toBase64(ciphertext)   // "SGVsbG8gd29ybGQ="
const decoded = fromBase64(encoded)     // Uint8Array

// URL-safe base64 — for URLs, JWK coordinates, query params
const urlSafe = toBase64Url(ciphertext) // "SGVsbG8gd29ybGQ"
const back = fromBase64Url(urlSafe)     // Uint8Array
```

## Notes

- `toBase64` / `fromBase64` use standard base64 (`+`, `/`, `=` padding).
- `toBase64Url` / `fromBase64Url` use base64url (`-`, `_`, no padding) — safe in URLs and JWKs.
- Both accept `ArrayBuffer` or `Uint8Array` as input.
- `fromBase64` and `fromBase64Url` always return a `Uint8Array`.
