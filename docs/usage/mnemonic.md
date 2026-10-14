# generateMnemonic / recoverWithMnemonic

BIP-39 mnemonic for account recovery when both passphrase and wrapped key are lost.

## Signatures

```ts
generateMnemonic(): string
recoverWithMnemonic(mnemonic: string, extractable?: boolean): Promise<CryptoKey>
```

## Example

```ts
import { generateMnemonic, recoverWithMnemonic } from '@consealdev/conseal'

// Account setup: generate mnemonic, show it once for the user to write down
const mnemonic = generateMnemonic()
// "apple crab moon tide lamp surge ... (24 words)"
// Display to user — never store server-side

// Recovery: user enters their 24 words
const aek = await recoverWithMnemonic('apple crab moon tide ...')
// Same mnemonic always produces the same AEK
```

## Notes

- The mnemonic is 24 words (256 bits of entropy). Show it once; the user must write it down.
- `recoverWithMnemonic()` is deterministic — same mnemonic always produces the same AEK.
- Throws if the phrase fails BIP-39 checksum validation.
- The AEK is derived from the mnemonic (HKDF-SHA-256), not the other way round: `initCircle(mnemonic, …)` derives a circle's AEK from it, and only a key derived this way can be recovered from a mnemonic.
- Pass `extractable: true` to wrap the recovered key with `wrapKey`, for example under a new passphrase.
- This is a last-resort recovery path. The primary path is `init()` with the wrapped key.
