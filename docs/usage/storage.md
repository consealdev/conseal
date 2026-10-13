# saveCryptoKey / loadCryptoKey / deleteCryptoKey

IndexedDB persistence for CryptoKey objects.

## Signatures

```ts
saveCryptoKey(name: string, key: CryptoKey): Promise<void>
loadCryptoKey(name: string): Promise<CryptoKey | null>
deleteCryptoKey(name: string): Promise<void>
```

## Example

```ts
import { saveCryptoKey, loadCryptoKey, deleteCryptoKey } from '@consealdev/conseal'

// Store a key after generation
await saveCryptoKey('my-ecdh-private', keyPair.privateKey)

// Load it on next page load
const key = await loadCryptoKey('my-ecdh-private')
if (!key) {
  // Key not found — prompt user to set up device again
}

// Remove on sign-out
await deleteCryptoKey('my-ecdh-private')
```

## Notes

- Uses IndexedDB database `conseal-keys`, object store `keys`.
- `loadCryptoKey()` returns `null` if the name does not exist — always check the return value.
- `deleteCryptoKey()` is a no-op if the name does not exist.
- Non-extractable keys cannot have their bytes read, but same-origin JavaScript can load and use them. XSS prevention is the application's responsibility.
