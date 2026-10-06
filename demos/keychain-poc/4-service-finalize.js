/**
 * Keychain PoC — Step 4: Service finalizes join and sends an encrypted reply
 *
 * - Loads service state from service-state.json
 * - Fetches the sealed AEK from the relay
 * - Calls finalizeJoin() to recover the AEK and verify the commitment (tamper check)
 * - Re-wraps the AEK under the service's own credentials
 * - Fetches the human's ECDH public key from the relay
 * - Seals a reply message for the human using sealMessage()
 * - Posts the encrypted reply to the relay
 *
 * The relay never sees the AEK, the service passphrase, or the plaintext reply.
 *
 * Run: node demos/keychain-poc/4-service-finalize.js
 */

import {
    finalizeJoin,
    unwrapKey,
    sealMessage,
    importPublicKeyFromJwk,
    fromBase64,
    toBase64,
} from '../../dist/index.js'

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const __dir = dirname(fileURLToPath(import.meta.url))
const RELAY = 'http://localhost:4400'

async function get(key) {
    const res = await fetch(`${RELAY}/fetch/${key}`)
    if (!res.ok) throw new Error(`relay GET /fetch/${key} failed: ${res.status}`)
    return res.json()
}

async function post(key, value) {
    const res = await fetch(`${RELAY}/store/${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(value),
    })
    if (!res.ok) throw new Error(`relay POST /store/${key} failed: ${res.status}`)
}

async function main() {
    console.log('=== Step 4: Service finalizes join and sends encrypted reply ===\n')

    const state = JSON.parse(readFileSync(join(__dir, 'service-state.json'), 'utf8'))
    const serviceSecretKey = fromBase64(state.secretKey)

    // Fetch sealed AEK from relay
    const sealedAEKPayload = await get('sealed-aek')
    console.log('[service] fetched sealed AEK from relay')

    // Reconstruct the ephemeral private key that was generated in step 2
    const ephemeralPrivateKey = await crypto.subtle.importKey(
        'jwk',
        state.ephemeralPrivateKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey']
    )

    // Reconstruct sealed AEK and commitment from stored base64
    const sealedAEK = {
        ciphertext: fromBase64(sealedAEKPayload.ciphertext).buffer,
        iv: fromBase64(sealedAEKPayload.iv),
        ephemeralPublicKey: sealedAEKPayload.ephemeralPublicKey,
    }
    const aekCommitment = fromBase64(sealedAEKPayload.aekCommitment).buffer

    // Finalize join — recovers the AEK via ECDH, verifies the commitment, re-wraps
    // under the service's own passphrase + secretKey.
    // Throws if the AEK commitment does not match (tamper detection).
    const { wrappedAEK } = await finalizeJoin(
        sealedAEK,
        ephemeralPrivateKey,
        state.passphrase,
        serviceSecretKey,
        aekCommitment
    )
    console.log('[service] AEK recovered and commitment verified ✓  (tamper check passed)')
    console.log('[service] AEK re-wrapped under service credentials')

    // Unwrap the AEK for use — the service can now seal data with it
    const aek = await unwrapKey(state.passphrase, wrappedAEK.wrappedKey, wrappedAEK.salt, serviceSecretKey)
    console.log('[service] AEK unwrapped for use\n')

    // Fetch human's long-term ECDH public key from the relay
    const manifest = await get('scope-manifest')
    const humanEcdhPublicKey = await importPublicKeyFromJwk(manifest.humanEcdhPublicKey, 'ECDH')

    // Seal a reply specifically for the human's ECDH public key
    // Only the holder of the human's ECDH private key can decrypt this
    const plainReply = 'Hello from the analytics service. The relay never saw this message.'
    const { ciphertext, iv, ephemeralPublicKey } = await sealMessage(
        humanEcdhPublicKey,
        new TextEncoder().encode(plainReply)
    )

    await post('service-reply', {
        ciphertext: toBase64(new Uint8Array(ciphertext)),
        iv: toBase64(iv),
        ephemeralPublicKey,
    })

    console.log('[service] encrypted reply posted to relay')
    console.log(`[service] plaintext (only human can read): "${plainReply}"\n`)
    console.log('Next: run 5-human-read.js')
}

main().catch(err => { console.error(err); process.exit(1) })
