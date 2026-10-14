# generateSecretKey / combinePassphraseAndSecretKey

128-bit Secret Key — a second factor for AEK wrapping. Neither the passphrase nor the Secret Key alone can unwrap the AEK.

## Signatures

```ts
generateSecretKey(): Uint8Array
combinePassphraseAndSecretKey(passphrase: string, secretKey: Uint8Array): Promise<string>
```

## Example: account setup with Secret Key

```ts
import { generateSecretKey, wrapKey, unwrapKey, init } from '@consealdev/conseal'

// Account setup — generate once, store device-side and keep an offline copy
const secretKey = generateSecretKey()
localStorage.setItem('conseal_sk', btoa(String.fromCharCode(...secretKey)))

const aek = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
)
const { wrappedKey, salt } = await wrapKey('my-strong-passphrase', aek, secretKey)
// POST { wrappedKey: btoa(...), salt: btoa(...) } to server — Secret Key never leaves the device

// New device — load secretKey from localStorage, fetch wrappedKey + salt from server
const storedSk = Uint8Array.from(atob(localStorage.getItem('conseal_sk')!), c => c.charCodeAt(0))
await init(wrappedKey, salt, 'my-strong-passphrase', storedSk)
```

## Notes

- `generateSecretKey()` returns a fresh random `Uint8Array` of 16 bytes (128-bit). Call it once at account setup.
- Store the Secret Key in `localStorage` on each enrolled device for daily use (user only types their passphrase).
- Keep an offline copy (printed or saved to a password manager). Unwrapping needs both factors, so losing either one locks the user out unless they kept the mnemonic.
- The Secret Key never leaves the device — do not send it to the server.
- `combinePassphraseAndSecretKey()` is used internally by `wrapKey` / `unwrapKey` / `rekey` / `rekeySecretKey` when `secretKey` is passed. Calling it directly is only needed for advanced use cases.
