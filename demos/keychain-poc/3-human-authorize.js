/**
 * Keychain PoC — Step 3: Human authorizes the service
 *
 * - Loads private state from human-state.json
 * - Fetches the join request from the relay
 * - Derives and prints the verification code — confirm it matches step 2 output
 * - Calls authorizeJoin() to seal the AEK for the service's ephemeral public key
 * - Posts the sealed AEK to the relay (only the service's ephemeral private key can open it)
 *
 * Run: node demos/keychain-poc/3-human-authorize.js
 */

import {
    authorizeJoin,
    deriveVerificationCode,
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
    console.log('=== Step 3: Human authorizes the service ===\n')

    // Load human's private state (never left this machine)
    const state = JSON.parse(readFileSync(join(__dir, 'human-state.json'), 'utf8'))

    const secretKey = fromBase64(state.secretKey)
    const wrappedAEK = {
        wrappedKey: fromBase64(state.wrappedAEK.wrappedKey).buffer,
        salt: fromBase64(state.wrappedAEK.salt),
    }
    const aekCommitment = fromBase64(state.aekCommitment).buffer

    // Fetch join request from relay
    const { serverReceivedAt, ...joinRequest } = await get('join-request')
    console.log(`[human] join request from: ${joinRequest.deviceMeta?.name} (${joinRequest.deviceMeta?.platform})`)

    // Derive verification code from the service's ephemeral public key
    const code = await deriveVerificationCode(joinRequest.ephemeralPublicKey)
    console.log(`[human] verification code: ${code}`)
    console.log('  ^^^ This must match what the service printed in step 2.')
    console.log('  In a real UI the human would confirm this before proceeding.\n')

    // Authorize — seals the AEK for the service's ephemeral key via ECDH
    // Only the ephemeral private key held by the service can open the result
    const sealedAEK = await authorizeJoin(
        joinRequest,
        wrappedAEK,
        state.passphrase,
        secretKey,
        serverReceivedAt
    )
    console.log('[human] AEK sealed for service (only service ephemeral key can open this)')

    // Post sealed AEK + commitment to relay
    // The relay stores this blob but cannot open it
    await post('sealed-aek', {
        ciphertext: toBase64(new Uint8Array(sealedAEK.ciphertext)),
        iv: toBase64(sealedAEK.iv),
        ephemeralPublicKey: sealedAEK.ephemeralPublicKey,
        aekCommitment: toBase64(new Uint8Array(aekCommitment)),
    })
    console.log('[human] sealed AEK posted to relay\n')
    console.log('Next: run 4-service-finalize.js')
}

main().catch(err => { console.error(err); process.exit(1) })
