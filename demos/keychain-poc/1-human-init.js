/**
 * Keychain PoC — Step 1: Human initialises the scope
 *
 * - Generates the BIP-39 mnemonic (root of trust for this scope)
 * - Calls initCircle() to derive the AEK and wrap it
 * - Generates a long-term ECDH key pair so the service can send encrypted replies
 * - Posts the scope manifest (aekCommitment + human ECDH public key) to the relay
 * - Saves private state to human-state.json — this file NEVER reaches the relay
 *
 * Run: node demos/keychain-poc/1-human-init.js
 */

import {
    generateMnemonic,
    initCircle,
    generateECDHKeyPair,
    exportPublicKeyAsJwk,
    generateSecretKey,
    toBase64,
} from '../../dist/index.js'

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const __dir = dirname(fileURLToPath(import.meta.url))
const RELAY = 'http://localhost:4400'

// Hardcoded for demo clarity. In production this would be user-supplied.
const PASSPHRASE = 'correct-horse-battery-staple'

async function post(key, value) {
    const res = await fetch(`${RELAY}/store/${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(value),
    })
    if (!res.ok) throw new Error(`relay POST /store/${key} failed: ${res.status}`)
}

async function main() {
    console.log('=== Step 1: Human initialises the scope ===\n')

    // 1. Generate the scope root of trust
    const mnemonic = generateMnemonic()
    const secretKey = generateSecretKey()

    console.log('[human] mnemonic (store this safely — it is the recovery root):')
    console.log(`  ${mnemonic}\n`)

    // 2. Initialise circle — derives AEK deterministically from mnemonic, wraps it
    const { wrappedAEK, aekCommitment, deviceId } = await initCircle(mnemonic, PASSPHRASE, secretKey)
    console.log(`[human] scope initialised  deviceId: ${deviceId}`)

    // 3. Generate long-term ECDH key pair for receiving sealed messages
    const { publicKey, privateKey } = await generateECDHKeyPair()
    const humanEcdhPublicKey = await exportPublicKeyAsJwk(publicKey)
    // Private key is extractable (generated with extractable:true by generateECDHKeyPair)
    const humanEcdhPrivateKeyJwk = await crypto.subtle.exportKey('jwk', privateKey)

    // 4. Post scope manifest to relay — public info only, no key material
    await post('scope-manifest', {
        aekCommitment: toBase64(new Uint8Array(aekCommitment)),
        humanEcdhPublicKey,
    })
    console.log('[human] scope manifest posted to relay (aekCommitment + ECDH public key)')

    // 5. Save private state locally — never sent to the relay
    const state = {
        mnemonic,
        passphrase: PASSPHRASE,
        secretKey: toBase64(secretKey),
        wrappedAEK: {
            wrappedKey: toBase64(new Uint8Array(wrappedAEK.wrappedKey)),
            salt: toBase64(wrappedAEK.salt),
        },
        aekCommitment: toBase64(new Uint8Array(aekCommitment)),
        ecdhPrivateKey: humanEcdhPrivateKeyJwk,
        deviceId,
    }

    writeFileSync(join(__dir, 'human-state.json'), JSON.stringify(state, null, 4))
    console.log('[human] private state saved to human-state.json  (passphrase, secretKey, wrappedAEK, ecdhPrivateKey)')
    console.log('[human] none of the above was sent to the relay\n')
    console.log('Next: run 2-service-join.js')
}

main().catch(err => { console.error(err); process.exit(1) })
