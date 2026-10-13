# exportPublicKeyAsJwk / importPublicKeyFromJwk

JWK serialisation for public keys.

## Signatures

```ts
exportPublicKeyAsJwk(key: CryptoKey): Promise<JsonWebKey>
importPublicKeyFromJwk(jwk: JsonWebKey, algorithm: 'ECDH' | 'ECDSA'): Promise<CryptoKey>
```

## Example

```ts
import { exportPublicKeyAsJwk, importPublicKeyFromJwk } from '@consealdev/conseal'

// Export for server registry
const jwk = await exportPublicKeyAsJwk(myPublicKey)
await fetch('/keys/me', { method: 'PUT', body: JSON.stringify(jwk) })

// Import a recipient's public key
const data = await fetch('/keys/alice').then(r => r.json())
const aliceKey = await importPublicKeyFromJwk(data, 'ECDH')
```

## Notes

- Only export public keys. Never call this on a private key.
- Pass `'ECDH'` for keys used with `sealMessage`, `'ECDSA'` for keys used with `verify`.
