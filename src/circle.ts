// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * conseal/circle — Multi-device private communication.
 *
 * Establishes a bounded group of trusted devices that all hold the same
 * Account Encryption Key (AEK). Encrypted data written on any device can be
 * decrypted on any other device in the circle.
 *
 * Four exported functions cover the full device-registration ceremony:
 *
 *   initCircle()        — founding device generates the shared AEK
 *   createJoinRequest() — new device generates an ephemeral ECDH key pair
 *   authorizeJoin()     — trusted device seals the AEK for the new device
 *   finalizeJoin()      — new device unseals and re-wraps the AEK
 *
 * secretKey (Uint8Array) is required for all four functions — passphrase-only
 * wrapping does not meet the security bar for multi-device sync. Each device
 * must hold a Secret Key via one of the three SK strategies (OS keychain,
 * IndexedDB non-extractable, or WebAuthn PRF).
 *
 * Composes: aes.ts, pbkdf2.ts, ecdh.ts, jwk.ts, digest.ts
 * No custom cryptography — correct composition of audited primitives only.
 */

import { importAesKey } from './aes'
import { wrapKey, unwrapKey } from './pbkdf2'
import { generateECDHKeyPair, sealMessage, unsealMessage } from './ecdh'
import { importPublicKeyFromJwk, exportPublicKeyAsJwk } from './jwk'
import { digest } from './digest'
import { recoverWithMnemonic } from './mnemonic'
import { buffersEqual } from './compare'

/** Maximum age of a join request before it is considered stale (5 minutes). */
export const JOIN_TTL_MS = 5 * 60 * 1000

// ---------- Types ----------

/** Wrapped AEK — opaque blob stored server-side per device. */
export interface WrappedAEK {
  wrappedKey: ArrayBuffer
  salt: Uint8Array
}

/** Serializable join request payload sent by a new device to the backend. */
export interface JoinRequest {
  deviceId: string
  ephemeralPublicKey: JsonWebKey
  /**
   * ISO 8601 timestamp set by the joining device. `authorizeJoin` uses this to
   * reject stale requests, but the check is only as trustworthy as the device
   * that set the value. Callers should independently validate request freshness
   * server-side (e.g. record when the backend first received the request and
   * reject if that server-stamped age exceeds the TTL).
   */
  createdAt: string
  deviceMeta?: { name?: string; platform?: string }
}

/** AEK sealed for a specific device's ephemeral public key via ECDH. */
export interface SealedAEK {
  ciphertext: ArrayBuffer
  iv: Uint8Array
  ephemeralPublicKey: JsonWebKey // sealMessage's ephemeral key — not the joining device's
}

// ---------- Exported helpers ----------

/**
 * Derives a human-readable verification code from an ECDH public key JWK.
 *
 * Exports the key as its uncompressed point bytes (65 bytes for P-256),
 * SHA-256 hashes them, and formats the first 4 bytes as uppercase hex pairs
 * separated by dashes: e.g. "A3-4F-9C-12" (32 bits / ~4 billion possible codes).
 *
 * Both the new device (createJoinRequest) and the authorizing device
 * (authorizeJoin) call this with the same JWK and must get the same code.
 * The user confirms the codes match out-of-band before approval proceeds.
 *
 * 32-bit space makes brute-force injection of a matching fake key pair
 * infeasible within the 5-minute TTL window.
 */
export async function deriveVerificationCode(ephemeralPublicKey: JsonWebKey): Promise<string> {
  return formatVerificationCode(await digest(await exportRawPublicKey(ephemeralPublicKey)))
}

/** Exports an ECDH public key JWK as its uncompressed point bytes (65 bytes for P-256). */
export async function exportRawPublicKey(publicKey: JsonWebKey): Promise<ArrayBuffer> {
  const key = await importPublicKeyFromJwk(publicKey, 'ECDH')
  return crypto.subtle.exportKey('raw', key)
}

/** Formats the first 4 bytes of a hash as uppercase hex pairs separated by dashes: "A3-4F-9C-12". */
export function formatVerificationCode(hash: ArrayBuffer): string {
  const bytes = new Uint8Array(hash)
  const hex = (b: number) => b.toString(16).padStart(2, '0').toUpperCase()
  return `${hex(bytes[0]!)}-${hex(bytes[1]!)}-${hex(bytes[2]!)}-${hex(bytes[3]!)}`
}

// ---------- Ceremony API ----------

/**
 * Called once by the founding device when creating a new account.
 *
 * Derives the shared AEK from the mnemonic (so it can always be recovered),
 * publishes its SHA-256 commitment (so joining devices can verify the AEK was
 * not substituted), and wraps the AEK under the founding device's own
 * passphrase + secretKey.
 *
 * The mnemonic is the root of trust — it must be shown to the user at account
 * creation and never stored. The app stores wrappedAEK and aekCommitment on
 * the server.
 */
export async function initCircle(
  mnemonic: string,
  passphrase: string,
  secretKey: Uint8Array
): Promise<{ wrappedAEK: WrappedAEK; aekCommitment: ArrayBuffer; deviceId: string }> {
  const aek = await recoverWithMnemonic(mnemonic, true) // extractable: true — must be wrappable
  const rawAEK = await crypto.subtle.exportKey('raw', aek)
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by digest() and wrapKey().
  const aekCommitment = await digest(rawAEK)
  const { wrappedKey, salt } = await wrapKey(passphrase, aek, secretKey)
  const deviceId = crypto.randomUUID()
  return { wrappedAEK: { wrappedKey, salt }, aekCommitment, deviceId }
}

/**
 * Called by a new device that wants to join the circle.
 *
 * Generates an ephemeral ECDH P-256 key pair for the one-time ceremony.
 * The ephemeral private key is returned to the caller and must be held in
 * memory only — never persisted — until finalizeJoin completes.
 *
 * The verification code is derived from the ephemeral public key and must
 * be displayed prominently so the user can confirm it matches the code shown
 * on the authorizing device.
 */
export async function createJoinRequest(
  deviceMeta?: { name?: string; platform?: string }
): Promise<{
  request: JoinRequest
  ephemeralPrivateKey: CryptoKey
  verificationCode: string
}> {
  const { publicKey, privateKey } = await generateECDHKeyPair()
  const ephemeralPublicKey = await exportPublicKeyAsJwk(publicKey)
  const verificationCode = await deriveVerificationCode(ephemeralPublicKey)
  const deviceId = crypto.randomUUID()
  const request: JoinRequest = {
    deviceId,
    ephemeralPublicKey,
    createdAt: new Date().toISOString(),
    ...(deviceMeta ? { deviceMeta } : {}),
  }
  return { request, ephemeralPrivateKey: privateKey, verificationCode }
}

/**
 * Called by a trusted device to approve a new device joining the circle.
 *
 * Rejects stale join requests based on `serverReceivedAt` — the Unix-ms
 * timestamp recorded by the server when the join request first arrived.
 * Callers MUST pass the server-stamped time, not `joinRequest.createdAt`,
 * which is set by the joining device and can be forged.
 *
 * The caller must present the verification code from
 * joinRequest.ephemeralPublicKey and require explicit user confirmation that
 * it matches the code on the new device before calling this function —
 * calling without confirmation bypasses the primary MITM defence.
 *
 * Unwraps the AEK and seals its raw bytes for the new device's ephemeral
 * public key via ECDH. Only the ephemeral private key held by the new device
 * can open it.
 *
 * @param serverReceivedAt  Unix milliseconds — when the server first received
 *   this join request. Use `Date.now()` at receipt time on the server, NOT
 *   `new Date(joinRequest.createdAt).getTime()`. Passing the client-supplied
 *   timestamp defeats TTL enforcement.
 */
export async function authorizeJoin(
  joinRequest: JoinRequest,
  wrappedAEK: WrappedAEK,
  passphrase: string,
  secretKey: Uint8Array,
  serverReceivedAt: number
): Promise<SealedAEK> {
  const age = Date.now() - serverReceivedAt
  if (age > JOIN_TTL_MS) {
    throw new Error('authorizeJoin: join request has expired (older than 5 minutes)')
  }

  // Unwrap extractable so raw bytes can be transferred via ECDH
  const aek = await unwrapKey(passphrase, wrappedAEK.wrappedKey, wrappedAEK.salt, secretKey, true)
  const rawAEK = await crypto.subtle.exportKey('raw', aek)
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by sealMessage() and never returned.

  const recipientPublicKey = await importPublicKeyFromJwk(joinRequest.ephemeralPublicKey, 'ECDH')
  const { ciphertext, iv, ephemeralPublicKey } = await sealMessage(recipientPublicKey, rawAEK)
  return { ciphertext, iv, ephemeralPublicKey }
}

/**
 * Called by the new device after authorization.
 *
 * Unseals the AEK using the ephemeral private key generated in
 * createJoinRequest, verifies it against aekCommitment (SHA-256 of the raw
 * AEK published by initCircle), then re-wraps it under the new device's own
 * passphrase + secretKey. The ephemeral private key is not needed after this
 * call and should be discarded.
 *
 * Throws if the commitment check fails — the AEK was substituted or tampered
 * with in transit. Do not use the returned wrappedAEK if this throws.
 */
export async function finalizeJoin(
  sealedAEK: SealedAEK,
  ephemeralPrivateKey: CryptoKey,
  passphrase: string,
  secretKey: Uint8Array,
  aekCommitment: ArrayBuffer
): Promise<{ wrappedAEK: WrappedAEK }> {
  const rawAEK = await unsealMessage(
    ephemeralPrivateKey,
    sealedAEK.ciphertext,
    sealedAEK.iv,
    sealedAEK.ephemeralPublicKey
  )
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by digest() and importAesKey().

  const actualCommitment = await digest(rawAEK)
  if (!buffersEqual(new Uint8Array(actualCommitment), new Uint8Array(aekCommitment))) {
    throw new Error('finalizeJoin: AEK commitment mismatch — key may have been tampered with')
  }

  const aek = await importAesKey(rawAEK, true) // extractable: true for wrapKey
  const { wrappedKey, salt } = await wrapKey(passphrase, aek, secretKey)
  return { wrappedAEK: { wrappedKey, salt } }
}
