// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * BIP-39 mnemonic generation and AEK recovery.
 *
 * generateMnemonic() produces a 24-word BIP-39 phrase (256 bits of entropy).
 * The user must store this phrase securely — it is the last-resort recovery path
 * when both the passphrase and the wrapped key are lost.
 *
 * recoverWithMnemonic() derives a deterministic AES-256-GCM key from the mnemonic's
 * entropy bytes. The same mnemonic always produces the same key — this is what makes
 * recovery possible.
 *
 * Dependency: @scure/bip39 (browser-compatible, audited)
 */

import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

/** Generates a fresh 24-word BIP-39 mnemonic (256 bits of entropy). */
export function generateMnemonic(): string {
  // Use the browser's crypto.getRandomValues directly instead of @noble/hashes randomBytes
  // (which accesses globalThis.crypto and triggers false "network access" warnings on socket.dev)
  const entropy = crypto.getRandomValues(new Uint8Array(32)) // 256 bits → 24 words
  return entropyToMnemonic(entropy, wordlist)
}

/**
 * Derives a deterministic AES-256-GCM CryptoKey from a BIP-39 mnemonic.
 * Throws if the mnemonic is invalid or not in the BIP-39 word list.
 *
 * The mnemonic's 32-byte entropy is passed through HKDF-SHA-256 with a
 * domain-separation label before being imported as key material. This adds
 * defense-in-depth: if the mnemonic came from a tool with weaker entropy, HKDF
 * still produces a well-distributed key; it also ensures key-domain separation
 * if the same entropy is ever used for another purpose.
 *
 * Pass extractable: true when the key must be wrapped before storage —
 * e.g. to re-wrap it under a new passphrase with wrapKey().
 */
export async function recoverWithMnemonic(mnemonic: string, extractable = false): Promise<CryptoKey> {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid mnemonic: phrase does not pass BIP-39 checksum validation')
  }
  // mnemonicToEntropy returns the raw entropy bytes — 32 bytes for a 24-word phrase
  // .slice() creates a copy backed by a plain ArrayBuffer (required by SubtleCrypto)
  const entropy = mnemonicToEntropy(mnemonic, wordlist).slice()
  // Import entropy as HKDF key material, then derive the AES-GCM key.
  // Empty salt is acceptable here because the IKM is already uniformly random
  // (crypto.getRandomValues); the info label provides domain separation.
  const hkdfKey = await crypto.subtle.importKey('raw', entropy, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('conseal-mnemonic-aek-v1'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  )
}
