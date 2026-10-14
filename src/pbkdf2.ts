// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * PBKDF2-SHA256 key derivation and AES-GCM key wrapping.
 *
 * wrapKey()        derives a wrapping key from a passphrase + random salt, exports the
 *                  target CryptoKey as raw bytes, and encrypts them with AES-GCM. A fresh
 *                  random IV is prepended to the ciphertext inside the returned wrappedKey,
 *                  and the salt is returned beside it. Neither is secret.
 *
 * unwrapKey()      reverses the process. Returns extractable: false unless asked — the
 *                  unwrapped key is safe to store in IndexedDB and use for encrypt/decrypt.
 *
 * rekey()          changes the passphrase without touching any encrypted content.
 *                  Unwraps the AEK with the old passphrase, re-wraps with the new one.
 *                  The AEK itself never changes.
 *
 * rekeySecretKey() rotates the Secret Key while keeping the passphrase the same.
 *                  Use this only when the Secret Key is compromised — it is a rare
 *                  operation equivalent to a full account re-setup.
 *
 * All four functions accept an optional secretKey (Uint8Array). When provided,
 * the passphrase is combined with the Secret Key by HMAC-SHA-256 before PBKDF2 runs.
 * Existing callers that pass no secretKey are unaffected.
 *
 * PBKDF2 parameters: 600,000 iterations, SHA-256, 128-bit random salt per call.
 * This is intentionally slow — it is the defence against offline brute-force if
 * the wrapped key is ever leaked.
 *
 * Note: AES-GCM is used instead of AES-KW because WebKit's SubtleCrypto does not
 * enforce the RFC 3394 integrity check on AES-KW unwrap, allowing wrong credentials
 * to silently return garbage key material. AES-GCM's authentication tag is validated
 * consistently across Chromium, Firefox, and WebKit.
 */

import { combinePassphraseAndSecretKey } from './secret-key'
import { buffersEqual } from './compare'

const ITERATIONS = 600_000
const SALT_LENGTH = 16 // 128-bit salt
const IV_LENGTH = 12   // 96-bit IV for AES-GCM

async function deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function resolvePassphrase(passphrase: string, secretKey?: Uint8Array): Promise<string> {
  return secretKey ? combinePassphraseAndSecretKey(passphrase, secretKey) : passphrase
}

/**
 * Decrypts a wrapped key buffer and imports it as a CryptoKey.
 * The first IV_LENGTH bytes of wrappedKey are the AES-GCM IV; the rest is ciphertext.
 * AES-GCM authentication throws on wrong credentials across all engines.
 */
async function decryptWrappedKey(
  wrappingKey: CryptoKey,
  wrappedKey: ArrayBuffer,
  extractable: boolean
): Promise<CryptoKey> {
  const bytes = new Uint8Array(wrappedKey)
  const iv = bytes.slice(0, IV_LENGTH)
  const ciphertext = bytes.slice(IV_LENGTH)
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, ciphertext)
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt'])
}

/** Wraps a CryptoKey with a passphrase (and optional Secret Key). The input key must have extractable: true. */
export async function wrapKey(
  passphrase: string,
  key: CryptoKey,
  secretKey?: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  if (!key.extractable) {
    throw new Error('wrapKey: key must be extractable (extractable: true)')
  }
  const effective = await resolvePassphrase(passphrase, secretKey)
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const wrappingKey = await deriveWrappingKey(effective, salt)
  const raw = await crypto.subtle.exportKey('raw', key)
  // Raw key bytes live briefly in memory here; JavaScript provides no reliable
  // way to zero them, but they are consumed immediately by encrypt() and never returned.
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, raw)
  // Prepend the IV so unwrapKey needs no extra parameter
  const wrapped = new Uint8Array(IV_LENGTH + ciphertext.byteLength)
  wrapped.set(iv, 0)
  wrapped.set(new Uint8Array(ciphertext), IV_LENGTH)
  return { wrappedKey: wrapped.buffer.slice(wrapped.byteOffset, wrapped.byteOffset + wrapped.byteLength), salt }
}

/**
 * Unwraps a CryptoKey. Returns extractable: false by default.
 * Pass extractable: true only when the raw key bytes are needed for transfer
 * (e.g. circle join ceremony) — export and discard as quickly as possible.
 */
export async function unwrapKey(
  passphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  secretKey?: Uint8Array,
  extractable = false
): Promise<CryptoKey> {
  const effective = await resolvePassphrase(passphrase, secretKey)
  const wrappingKey = await deriveWrappingKey(effective, salt)
  return decryptWrappedKey(wrappingKey, wrappedKey, extractable)
}

/**
 * Changes the passphrase protecting the AEK without re-encrypting any content.
 * The Secret Key (if any) stays the same — it is used on both the unwrap and re-wrap sides.
 */
export async function rekey(
  oldPassphrase: string,
  newPassphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  secretKey?: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  const effectiveOld = await resolvePassphrase(oldPassphrase, secretKey)
  const oldWrappingKey = await deriveWrappingKey(effectiveOld, salt)
  const aek = await decryptWrappedKey(oldWrappingKey, wrappedKey, true)
  return wrapKey(newPassphrase, aek, secretKey)
}

/**
 * Rotates the Secret Key while keeping the passphrase the same.
 * Use only when the Secret Key is compromised — this is a rare, heavyweight operation.
 * Unwraps with passphrase + oldSecretKey, re-wraps with passphrase + newSecretKey.
 *
 * @param passphrase  - the passphrase (unchanged)
 * @param oldSecretKey - the current Secret Key (used to unwrap)
 * @param newSecretKey - the replacement Secret Key (used to re-wrap)
 * @param wrappedKey   - the currently wrapped AEK
 * @param salt         - the salt used when the AEK was wrapped
 */
export async function rekeySecretKey(
  passphrase: string,
  oldSecretKey: Uint8Array,
  newSecretKey: Uint8Array,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  if (buffersEqual(oldSecretKey, newSecretKey)) {
    throw new Error('rekeySecretKey: oldSecretKey and newSecretKey must be different')
  }
  const effectiveOld = await resolvePassphrase(passphrase, oldSecretKey)
  const oldWrappingKey = await deriveWrappingKey(effectiveOld, salt)
  const aek = await decryptWrappedKey(oldWrappingKey, wrappedKey, true)
  return wrapKey(passphrase, aek, newSecretKey)
}
