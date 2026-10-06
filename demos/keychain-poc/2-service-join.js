/**
 * Keychain PoC — Step 2: Service creates a join request
 *
 * - Calls createJoinRequest() to generate an ephemeral ECDH key pair
 * - Posts the join request to the relay with a server-stamped arrival time
 * - Prints the verification code — the human must confirm it matches before authorizing
 * - Saves ephemeral private key and service credentials to service-state.json
 *
 * Run: node demos/keychain-poc/2-service-join.js
 */

import {
    createJoinRequest,
    generateSecretKey,
    toBase64,
} from '../../dist/index.js'

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const __dir = dirname(fileURLToPath(import.meta.url))
const RELAY = 'http://localhost:4400'

// Service's own credentials for re-wrapping the AEK after finalizeJoin
const SERVICE_PASSPHRASE = 'service-internal-passphrase'

async function post(key, value) {
    const res = await fetch(`${RELAY}/store/${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(value),
    })
    if (!res.ok) throw new Error(`relay POST /store/${key} failed: ${res.status}`)
}

async function main() {
    console.log('=== Step 2: Service creates join request ===\n')

    const serviceSecretKey = generateSecretKey()

    // createJoinRequest generates an ephemeral ECDH key pair for the ceremony
    const { request: joinRequest, ephemeralPrivateKey, verificationCode } =
        await createJoinRequest({ name: 'analytics-service', platform: 'node' })

    console.log(`[service] verification code: ${verificationCode}`)
    console.log('  ^^^ The human must confirm this matches the code in step 3 before proceeding.\n')

    // Export ephemeral private key for use in step 4 (finalizeJoin)
    const ephemeralPrivateKeyJwk = await crypto.subtle.exportKey('jwk', ephemeralPrivateKey)

    // Post join request to relay — relay stamps the arrival time
    // The human will use serverReceivedAt to enforce the 5-minute TTL
    await post('join-request', {
        ...joinRequest,
        serverReceivedAt: Date.now(),
    })
    console.log('[service] join request posted to relay')

    // Save service state locally
    const state = {
        passphrase: SERVICE_PASSPHRASE,
        secretKey: toBase64(serviceSecretKey),
        verificationCode,
        joinRequest,
        ephemeralPrivateKey: ephemeralPrivateKeyJwk,
    }

    writeFileSync(join(__dir, 'service-state.json'), JSON.stringify(state, null, 4))
    console.log('[service] state saved to service-state.json')
    console.log('[service] ephemeral private key is local only — never sent to relay\n')
    console.log('Next: run 3-human-authorize.js  (confirm the verification code first)')
}

main().catch(err => { console.error(err); process.exit(1) })
