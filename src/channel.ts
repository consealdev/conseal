// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * conseal/channel — Shared encrypted spaces across users.
 *
 * A channel has its own random AES-256-GCM key, the channel AEK. Each member
 * holds it wrapped under their circle AEK, which every device in their circle
 * already has. Membership belongs to the user, not to a device: a device that
 * joins the circle later opens every channel the user is in, with no new invite.
 *
 * Six exported functions cover a channel's life:
 *
 *   createChannel()                 — the first member generates the channel AEK
 *   unwrapChannelAEK()              — any device of a member opens it
 *   createChannelJoinRequest()      — an invitee generates an ephemeral ECDH key pair
 *   deriveChannelVerificationCode() — a member derives the code for an invitee's request
 *   authorizeChannelJoin()          — a member seals the channel AEK for the invitee
 *   finalizeChannelJoin()           — the invitee unseals it and wraps it under their circle AEK
 *
 * An invite is the circle's join ceremony with one change: its verification
 * code covers the channel id and the channel's AEK commitment as well as the
 * ephemeral public key. The invitee takes the commitment before its key pair
 * exists, and the member computes it from the channel AEK it holds. A key
 * substituted on the way, with a commitment to match, changes the invitee's
 * code, so comparing the codes catches it.
 *
 * A wrapped channel AEK is IV (12 bytes) ‖ AES-GCM(circleAEK, raw channel AEK),
 * 60 bytes, with AAD = UTF-8("conseal-channel:v1:" + channelId). It opens only
 * as the channel it was wrapped for, and can't pass for any other key the
 * circle AEK wraps.
 *
 * Composes: aes.ts, ecdh.ts, jwk.ts, digest.ts, circle.ts
 * No custom cryptography — correct composition of audited primitives only.
 */

import { seal, unseal, generateAesKey, importAesKey } from './aes'
import { generateECDHKeyPair, sealMessage, unsealMessage } from './ecdh'
import { importPublicKeyFromJwk, exportPublicKeyAsJwk } from './jwk'
import { digest } from './digest'
import { buffersEqual } from './compare'
import { JOIN_TTL_MS, exportRawPublicKey, formatVerificationCode, type SealedAEK } from './circle'

const IV_LENGTH = 12
const COMMITMENT_LENGTH = 32
const WRAPPED_LENGTH = IV_LENGTH + 32 + 16 // IV ‖ the 32-byte key ‖ its 128-bit tag
const WRAP_LABEL = 'conseal-channel:v1:'
const CODE_LABEL = 'conseal-channel-invite:v1'

// ---------- Types ----------

/** Serializable request an invitee sends to the backend to join a channel. */
export interface ChannelJoinRequest {
  channelId: string
  ephemeralPublicKey: JsonWebKey
}

// ---------- Channel keys ----------

/**
 * Called once by the member who creates a channel.
 *
 * Generates a random channel AEK, wraps it under the member's circle AEK, and
 * publishes its SHA-256 commitment. The app stores wrappedChannelAEK as this
 * member's copy and aekCommitment for the channel, both server-side; an
 * invitee needs the commitment before it asks to join.
 *
 * Unlike initCircle(), the channel AEK isn't derived from a mnemonic. It lives
 * in its members' wrapped copies, and each copy opens with that member's circle
 * AEK, which their own mnemonic recovers.
 */
export async function createChannel(circleAEK: CryptoKey): Promise<{
  channelId: string
  channelAEK: CryptoKey
  wrappedChannelAEK: ArrayBuffer
  aekCommitment: ArrayBuffer
}> {
  const channelId = crypto.randomUUID()
  const key = await generateAesKey(true) // extractable: true — the raw bytes are wrapped and committed to
  const rawAEK = await crypto.subtle.exportKey('raw', key)
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by wrap(), digest() and importAesKey().
  const wrappedChannelAEK = await wrap(circleAEK, channelId, rawAEK)
  const aekCommitment = await digest(rawAEK)
  const channelAEK = await importAesKey(rawAEK)
  return { channelId, channelAEK, wrappedChannelAEK, aekCommitment }
}

/**
 * Called by any device of a member to open a channel.
 *
 * Unwraps the member's wrappedChannelAEK with their circle AEK and returns the
 * channel AEK, non-extractable. Throws if the wrapped key was tampered with,
 * was wrapped for another channel, or under another circle AEK.
 */
export async function unwrapChannelAEK(
  channelId: string,
  wrappedChannelAEK: ArrayBuffer | Uint8Array,
  circleAEK: CryptoKey
): Promise<CryptoKey> {
  const rawAEK = await unwrap('unwrapChannelAEK', circleAEK, channelId, wrappedChannelAEK)
  return importAesKey(rawAEK)
}

// ---------- Invite ceremony ----------

/**
 * Called by a user who wants to join a channel.
 *
 * Takes the channel's id and aekCommitment, from the invite or the backend,
 * then generates an ephemeral ECDH P-256 key pair for the one-time ceremony.
 * The order matters: the commitment is fixed before the key pair exists, so
 * whoever supplied it can't choose it after seeing the key. Hold the ephemeral
 * private key and the commitment in memory only, until finalizeChannelJoin
 * completes.
 *
 * The verification code covers the channel id, the commitment and the
 * ephemeral public key. Display it prominently: the user must confirm it
 * matches the code on the inviting member's device before finalizing.
 */
export async function createChannelJoinRequest(
  channelId: string,
  aekCommitment: ArrayBuffer | Uint8Array
): Promise<{
  request: ChannelJoinRequest
  ephemeralPrivateKey: CryptoKey
  verificationCode: string
}> {
  requireChannelId('createChannelJoinRequest', channelId)
  requireCommitment('createChannelJoinRequest', aekCommitment)
  const { publicKey, privateKey } = await generateECDHKeyPair()
  const ephemeralPublicKey = await exportPublicKeyAsJwk(publicKey)
  const verificationCode = await channelCode(channelId, aekCommitment, ephemeralPublicKey)
  return { request: { channelId, ephemeralPublicKey }, ephemeralPrivateKey: privateKey, verificationCode }
}

/**
 * Called by a member to show the verification code for an invitee's request.
 *
 * Computes the channel's commitment from the channel AEK this member holds,
 * never from a value the backend supplies, so the code matches the invitee's
 * only when both hold the same channel id, commitment and ephemeral public
 * key. Present it and require explicit user confirmation that it matches the
 * invitee's code before calling authorizeChannelJoin — authorizing without
 * that confirmation bypasses the ceremony's defence against a substituted key.
 */
export async function deriveChannelVerificationCode(
  joinRequest: ChannelJoinRequest,
  wrappedChannelAEK: ArrayBuffer | Uint8Array,
  circleAEK: CryptoKey
): Promise<string> {
  const rawAEK = await unwrap('deriveChannelVerificationCode', circleAEK, joinRequest.channelId, wrappedChannelAEK)
  return channelCode(joinRequest.channelId, await digest(rawAEK), joinRequest.ephemeralPublicKey)
}

/**
 * Called by a member to admit an invitee, once the user has confirmed the codes match.
 *
 * Rejects stale requests based on `serverReceivedAt` — the Unix-ms time the
 * server first received the request. Callers MUST pass the server-stamped
 * time, never one the invitee supplied.
 *
 * Unwraps the channel AEK and seals its raw bytes for the invitee's ephemeral
 * public key via ECDH. Only the invitee's ephemeral private key can open it.
 */
export async function authorizeChannelJoin(
  joinRequest: ChannelJoinRequest,
  wrappedChannelAEK: ArrayBuffer | Uint8Array,
  circleAEK: CryptoKey,
  serverReceivedAt: number
): Promise<SealedAEK> {
  const age = Date.now() - serverReceivedAt
  if (age > JOIN_TTL_MS) {
    throw new Error('authorizeChannelJoin: join request has expired (older than 5 minutes)')
  }

  const rawAEK = await unwrap('authorizeChannelJoin', circleAEK, joinRequest.channelId, wrappedChannelAEK)
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by sealMessage() and never returned.
  const recipientPublicKey = await importPublicKeyFromJwk(joinRequest.ephemeralPublicKey, 'ECDH')
  const { ciphertext, iv, ephemeralPublicKey } = await sealMessage(recipientPublicKey, rawAEK)
  return { ciphertext, iv, ephemeralPublicKey }
}

/**
 * Called by the invitee after authorization.
 *
 * Unseals the channel AEK with the ephemeral private key from
 * createChannelJoinRequest, verifies it against the aekCommitment the request
 * was created with, then wraps it under the invitee's circle AEK. The app
 * stores wrappedChannelAEK as this member's copy, and every device in the
 * invitee's circle can open it. The ephemeral private key is not needed after
 * this call and should be discarded.
 *
 * Throws if the commitment check fails — the key was substituted or tampered
 * with in transit. Store nothing if this throws.
 */
export async function finalizeChannelJoin(
  sealedAEK: SealedAEK,
  ephemeralPrivateKey: CryptoKey,
  circleAEK: CryptoKey,
  channelId: string,
  aekCommitment: ArrayBuffer | Uint8Array
): Promise<{ channelAEK: CryptoKey; wrappedChannelAEK: ArrayBuffer }> {
  requireChannelId('finalizeChannelJoin', channelId)
  requireCommitment('finalizeChannelJoin', aekCommitment)
  const rawAEK = await unsealMessage(
    ephemeralPrivateKey,
    sealedAEK.ciphertext,
    sealedAEK.iv,
    sealedAEK.ephemeralPublicKey
  )
  // Raw AEK bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by digest(), wrap() and importAesKey().

  const actualCommitment = await digest(rawAEK)
  if (!buffersEqual(new Uint8Array(actualCommitment), bytesOf(aekCommitment))) {
    throw new Error('finalizeChannelJoin: channel AEK commitment mismatch — key may have been tampered with')
  }

  const wrappedChannelAEK = await wrap(circleAEK, channelId, rawAEK)
  const channelAEK = await importAesKey(rawAEK)
  return { channelAEK, wrappedChannelAEK }
}

// ---------- Internal ----------

async function wrap(circleAEK: CryptoKey, channelId: string, rawAEK: ArrayBuffer): Promise<ArrayBuffer> {
  const { ciphertext, iv } = await seal(circleAEK, rawAEK, wrapAad(channelId))
  // Prepend the IV, as wrapKey does, so a wrapped key is a single value
  const wrapped = new Uint8Array(IV_LENGTH + ciphertext.byteLength)
  wrapped.set(iv, 0)
  wrapped.set(new Uint8Array(ciphertext), IV_LENGTH)
  return wrapped.buffer
}

async function unwrap(
  caller: string,
  circleAEK: CryptoKey,
  channelId: string,
  wrappedChannelAEK: ArrayBuffer | Uint8Array
): Promise<ArrayBuffer> {
  requireChannelId(caller, channelId)
  const bytes = bytesOf(wrappedChannelAEK)
  if (bytes.byteLength !== WRAPPED_LENGTH) {
    throw new TypeError(`${caller}: wrapped channel AEK must be ${WRAPPED_LENGTH} bytes, got ${bytes.byteLength}`)
  }
  return unseal(circleAEK, bytes.slice(IV_LENGTH).buffer, bytes.slice(0, IV_LENGTH), wrapAad(channelId))
}

function wrapAad(channelId: string): Uint8Array {
  return new TextEncoder().encode(WRAP_LABEL + channelId)
}

/**
 * SHA-256 over the label, the commitment, the ephemeral public key's point and
 * the channel id, formatted like the circle's codes. Every field but the last
 * has a fixed length, so the input splits only one way.
 */
async function channelCode(
  channelId: string,
  aekCommitment: ArrayBuffer | Uint8Array,
  ephemeralPublicKey: JsonWebKey
): Promise<string> {
  const encoder = new TextEncoder()
  const parts = [
    encoder.encode(CODE_LABEL),
    bytesOf(aekCommitment),
    new Uint8Array(await exportRawPublicKey(ephemeralPublicKey)),
    encoder.encode(channelId),
  ]
  const input = new Uint8Array(parts.reduce((length, part) => length + part.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    input.set(part, offset)
    offset += part.byteLength
  }
  return formatVerificationCode(await digest(input))
}

function requireChannelId(caller: string, channelId: string): void {
  if (typeof channelId !== 'string' || channelId.length === 0) {
    throw new TypeError(`${caller}: channelId must be a non-empty string`)
  }
}

function requireCommitment(caller: string, aekCommitment: ArrayBuffer | Uint8Array): void {
  if (aekCommitment.byteLength !== COMMITMENT_LENGTH) {
    throw new TypeError(`${caller}: aekCommitment must be ${COMMITMENT_LENGTH} bytes (SHA-256), got ${aekCommitment.byteLength}`)
  }
}

function bytesOf(data: ArrayBuffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data)
}
