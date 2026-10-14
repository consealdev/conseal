// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * New device setup orchestrator.
 *
 * init() is called once per device when a user signs in on a new device.
 * It unwraps the AEK using the user's passphrase (and optional Secret Key)
 * and persists it to IndexedDB under AEK_KEY_ID, where subsequent operations
 * (seal, unseal, sealMessage, etc.) can load it via loadCryptoKey(AEK_KEY_ID).
 *
 * The wrappedKey + salt are fetched from the server (Option A) or uploaded by
 * the user as a key file (Option B) before calling init().
 */

import { unwrapKey } from './pbkdf2'
import { saveCryptoKey, AEK_KEY_ID } from './storage'

/** The IndexedDB key id under which the AEK is stored after init(). Re-exported from storage. */
export { AEK_KEY_ID }

/**
 * Unwraps the AEK with the given passphrase (and optional Secret Key) and
 * stores it in IndexedDB. After this completes, the AEK is available via
 * loadCryptoKey(AEK_KEY_ID).
 */
export async function init(
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  passphrase: string,
  secretKey?: Uint8Array
): Promise<void> {
  const aek = await unwrapKey(passphrase, wrappedKey, salt, secretKey)
  await saveCryptoKey(AEK_KEY_ID, aek)
}
