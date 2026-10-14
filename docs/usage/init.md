# init / AEK_KEY_ID

New device setup. Unwraps the AEK with the user's passphrase (and optional Secret Key) and stores it in IndexedDB.

## Signatures

```ts
init(wrappedKey: ArrayBuffer, salt: Uint8Array, passphrase: string, secretKey?: Uint8Array): Promise<void>
AEK_KEY_ID: string  // 'aek'
```

## Example

```ts
import { init, AEK_KEY_ID, loadCryptoKey, seal } from '@consealdev/conseal'

// On new device after OAuth login:
// 1. Fetch wrappedKey + salt from server (or accept user key file upload)
const resp = await fetch('/account/wrapped-key').then(r => r.json())
const wrappedKey = Uint8Array.from(atob(resp.wrappedKey), c => c.charCodeAt(0)).buffer
const salt = Uint8Array.from(atob(resp.salt), c => c.charCodeAt(0))

// 2. Prompt user for their passphrase (Secret Key loaded from localStorage if enrolled)
await init(wrappedKey, salt, userPassphrase)

// 3. AEK is now in IndexedDB — load and use it
const aek = await loadCryptoKey(AEK_KEY_ID)
const { ciphertext, iv } = await seal(aek!, plaintext)
```

## Example: with Secret Key

```ts
import { init, AEK_KEY_ID, loadCryptoKey } from '@consealdev/conseal'

// Load Secret Key from localStorage (stored at account setup)
const secretKey = Uint8Array.from(atob(localStorage.getItem('conseal_sk')!), c => c.charCodeAt(0))

await init(wrappedKey, salt, userPassphrase, secretKey)
const aek = await loadCryptoKey(AEK_KEY_ID)
```

## Notes

- Throws if the passphrase is wrong.
- Throws if the passphrase is correct but the Secret Key is wrong or missing when one was used at setup.
- After `init()`, the AEK is stored under `AEK_KEY_ID` (`'aek'`).
