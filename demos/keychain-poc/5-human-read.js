/**
 * Keychain PoC — Step 5: Human reads the encrypted reply
 *
 * - Loads private state from human-state.json
 * - Fetches the encrypted reply from the relay
 * - Decrypts using the human's ECDH private key
 * - Prints the plaintext
 *
 * The relay held this ciphertext the whole time and could not read it.
 *
 * Run: node demos/keychain-poc/5-human-read.js
 */

import {
    unsealMessage,
    fromBase64,
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

async function main() {
    console.log('=== Step 5: Human reads the encrypted reply ===\n')

    const state = JSON.parse(readFileSync(join(__dir, 'human-state.json'), 'utf8'))

    // Reconstruct the human's long-term ECDH private key from JWK
    const ecdhPrivateKey = await crypto.subtle.importKey(
        'jwk',
        state.ecdhPrivateKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey']
    )

    // Fetch encrypted reply from relay
    const reply = await get('service-reply')
    console.log('[human] fetched encrypted reply from relay')

    // Decrypt — only the human's ECDH private key can do this
    const plaintext = await unsealMessage(
        ecdhPrivateKey,
        fromBase64(reply.ciphertext).buffer,
        fromBase64(reply.iv),
        reply.ephemeralPublicKey
    )

    const message = new TextDecoder().decode(plaintext)
    console.log('[human] decrypted reply:')
    console.log(`  "${message}"\n`)

    console.log('--- Proof summary ---')
    console.log('✓ Human created a scope. Service joined via the circle ceremony.')
    console.log('✓ Service encrypted a message for the human\'s ECDH public key.')
    console.log('✓ Human decrypted it using only their local private key.')
    console.log('✓ The relay held every blob in this exchange and could read none of it.')
    console.log('  Check the relay log to verify: only base64 blobs, no plaintext, no key material.')
}

main().catch(err => { console.error(err); process.exit(1) })
