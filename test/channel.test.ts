import { describe, it, expect, beforeAll } from 'vitest'
import { generateAesKey, seal, unseal } from '../src/aes'
import { unwrapKey } from '../src/pbkdf2'
import { generateECDHKeyPair, sealMessage } from '../src/ecdh'
import { importPublicKeyFromJwk } from '../src/jwk'
import { digest } from '../src/digest'
import { generateMnemonic } from '../src/mnemonic'
import {
  initCircle,
  createJoinRequest,
  authorizeJoin,
  finalizeJoin,
  deriveVerificationCode,
  formatVerificationCode,
} from '../src/circle'
import {
  createChannel,
  unwrapChannelAEK,
  createChannelJoinRequest,
  deriveChannelVerificationCode,
  authorizeChannelJoin,
  finalizeChannelJoin,
  type ChannelJoinRequest,
} from '../src/channel'
import * as conseal from '../src/index'

// ---------- helpers ----------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const CODE = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/

/** A member's circle AEK, as every device in their circle holds it. */
function circleKey(): Promise<CryptoKey> {
  return generateAesKey()
}

function text(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer as ArrayBuffer
}

async function sealText(key: CryptoKey, value: string) {
  return seal(key, text(value))
}

async function openText(key: CryptoKey, sealed: { ciphertext: ArrayBuffer; iv: Uint8Array }): Promise<string> {
  return new TextDecoder().decode(await unseal(key, sealed.ciphertext, sealed.iv))
}

function flipByte(buffer: ArrayBuffer, index: number): ArrayBuffer {
  const bytes = new Uint8Array(buffer.slice(0))
  bytes[index] = bytes[index]! ^ 0xff
  return bytes.buffer
}

/** Another 32-byte key wrapped under the circle AEK in the same layout, IV ‖ AES-GCM, with its own AAD or none. */
async function wrapOtherKey(circleAEK: CryptoKey, aad?: string): Promise<ArrayBuffer> {
  const raw = crypto.getRandomValues(new Uint8Array(32))
  const additionalData = aad === undefined ? undefined : new TextEncoder().encode(aad)
  const { ciphertext, iv } = await seal(circleAEK, raw.buffer as ArrayBuffer, additionalData)
  const wrapped = new Uint8Array(iv.byteLength + ciphertext.byteLength)
  wrapped.set(iv, 0)
  wrapped.set(new Uint8Array(ciphertext), iv.byteLength)
  return wrapped.buffer
}

/** The whole invite, with the codes compared: returns the invitee's copy. */
async function invite(
  channel: { channelId: string; wrappedChannelAEK: ArrayBuffer; aekCommitment: ArrayBuffer },
  inviterCircle: CryptoKey,
  inviteeCircle: CryptoKey
) {
  const { request, ephemeralPrivateKey, verificationCode } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
  const inviterCode = await deriveChannelVerificationCode(request, channel.wrappedChannelAEK, inviterCircle)
  expect(inviterCode).toBe(verificationCode)
  const sealed = await authorizeChannelJoin(request, channel.wrappedChannelAEK, inviterCircle, Date.now())
  return finalizeChannelJoin(sealed, ephemeralPrivateKey, inviteeCircle, channel.channelId, channel.aekCommitment)
}

// ---------- createChannel ----------

describe('createChannel', () => {
  it('returns a UUID channelId, a 60-byte wrapped key and a 32-byte commitment', async () => {
    const channel = await createChannel(await circleKey())
    expect(channel.channelId).toMatch(UUID)
    expect(channel.wrappedChannelAEK).toBeInstanceOf(ArrayBuffer)
    expect(channel.wrappedChannelAEK.byteLength).toBe(60)
    expect(channel.aekCommitment).toBeInstanceOf(ArrayBuffer)
    expect(channel.aekCommitment.byteLength).toBe(32)
  })

  it('returns a non-extractable channel AEK that its wrapped copy opens', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    expect(channel.channelAEK.extractable).toBe(false)
    expect(channel.channelAEK.algorithm.name).toBe('AES-GCM')

    const sealed = await sealText(channel.channelAEK, 'hello channel')
    const opened = await unwrapChannelAEK(channel.channelId, channel.wrappedChannelAEK, circle)
    expect(await openText(opened, sealed)).toBe('hello channel')
  })

  it('makes a new id and key on each call', async () => {
    const circle = await circleKey()
    const a = await createChannel(circle)
    const b = await createChannel(circle)
    expect(a.channelId).not.toBe(b.channelId)
    expect(new Uint8Array(a.aekCommitment)).not.toEqual(new Uint8Array(b.aekCommitment))
  })

  it('throws on a circle key that is not AES-GCM', async () => {
    const { privateKey } = await generateECDHKeyPair()
    await expect(createChannel(privateKey)).rejects.toThrow(TypeError)
  })
})

// ---------- unwrapChannelAEK ----------

describe('unwrapChannelAEK', () => {
  it('returns a non-extractable key', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const key = await unwrapChannelAEK(channel.channelId, channel.wrappedChannelAEK, circle)
    expect(key.extractable).toBe(false)
  })

  it('accepts the wrapped key as a Uint8Array', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const sealed = await sealText(channel.channelAEK, 'bytes')
    const key = await unwrapChannelAEK(channel.channelId, new Uint8Array(channel.wrappedChannelAEK), circle)
    expect(await openText(key, sealed)).toBe('bytes')
  })

  it('throws under another circle AEK', async () => {
    const channel = await createChannel(await circleKey())
    await expect(unwrapChannelAEK(channel.channelId, channel.wrappedChannelAEK, await circleKey())).rejects.toThrow()
  })

  it('throws when the id is another channel\'s', async () => {
    const circle = await circleKey()
    const a = await createChannel(circle)
    const b = await createChannel(circle)
    await expect(unwrapChannelAEK(b.channelId, a.wrappedChannelAEK, circle)).rejects.toThrow()
  })

  it('throws when the wrapped key was tampered with', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    for (const index of [0, 12, 59]) {
      await expect(unwrapChannelAEK(channel.channelId, flipByte(channel.wrappedChannelAEK, index), circle)).rejects.toThrow()
    }
  })

  it('refuses another key the circle AEK wrapped', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    // A record's DEK as conseal-sync wraps it, and a key wrapped with no AAD
    const recordKey = await wrapOtherKey(circle, 'conseal-sync:v1:7f3a9c21:0b6e6a52-6f4c-4c2e-9d0a-5d3f7c1e2b9a')
    const bareKey = await wrapOtherKey(circle)
    for (const wrapped of [recordKey, bareKey]) {
      expect(wrapped.byteLength).toBe(60)
      await expect(unwrapChannelAEK(channel.channelId, wrapped, circle)).rejects.toThrow()
    }
  })

  it('throws a TypeError for a wrapped key of the wrong length', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    await expect(unwrapChannelAEK(channel.channelId, channel.wrappedChannelAEK.slice(0, 59), circle)).rejects.toThrow(TypeError)
  })

  it('throws a TypeError for an empty channel id', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    await expect(unwrapChannelAEK('', channel.wrappedChannelAEK, circle)).rejects.toThrow(TypeError)
  })
})

// ---------- createChannelJoinRequest ----------

describe('createChannelJoinRequest', () => {
  it('returns the request, the ephemeral private key and a verification code', async () => {
    const channel = await createChannel(await circleKey())
    const { request, ephemeralPrivateKey, verificationCode } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    expect(request.channelId).toBe(channel.channelId)
    expect(request.ephemeralPublicKey.kty).toBe('EC')
    expect(request.ephemeralPublicKey.d).toBeUndefined()
    expect(ephemeralPrivateKey.type).toBe('private')
    expect(ephemeralPrivateKey.algorithm.name).toBe('ECDH')
    expect(verificationCode).toMatch(CODE)
  })

  it('derives the code from the label, the commitment, the key\'s point and the channel id', async () => {
    const channel = await createChannel(await circleKey())
    const { request, verificationCode } = await createChannelJoinRequest(channel.channelId, new Uint8Array(channel.aekCommitment))

    const key = await importPublicKeyFromJwk(request.ephemeralPublicKey, 'ECDH')
    const point = new Uint8Array(await crypto.subtle.exportKey('raw', key))
    const label = new TextEncoder().encode('conseal-channel-invite:v1')
    const id = new TextEncoder().encode(channel.channelId)
    const input = new Uint8Array([...label, ...new Uint8Array(channel.aekCommitment), ...point, ...id])

    expect(point.byteLength).toBe(65)
    expect(verificationCode).toBe(formatVerificationCode(await digest(input)))
  })

  it('gives a code unlike the circle\'s for the same ephemeral key', async () => {
    const channel = await createChannel(await circleKey())
    const { request, verificationCode } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    expect(await deriveVerificationCode(request.ephemeralPublicKey)).not.toBe(verificationCode)
  })

  it('throws a TypeError for a commitment that is not 32 bytes', async () => {
    const channel = await createChannel(await circleKey())
    await expect(createChannelJoinRequest(channel.channelId, channel.aekCommitment.slice(0, 31))).rejects.toThrow(TypeError)
  })

  it('throws a TypeError for an empty channel id', async () => {
    const channel = await createChannel(await circleKey())
    await expect(createChannelJoinRequest('', channel.aekCommitment)).rejects.toThrow(TypeError)
  })
})

// ---------- deriveChannelVerificationCode ----------

describe('deriveChannelVerificationCode', () => {
  it('matches the invitee\'s code', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request, verificationCode } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    expect(await deriveChannelVerificationCode(request, channel.wrappedChannelAEK, circle)).toBe(verificationCode)
  })

  it('differs when the request reaching the member carries another ephemeral key', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const invitee = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const relayed = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const code = await deriveChannelVerificationCode(relayed.request, channel.wrappedChannelAEK, circle)
    expect(code).not.toBe(invitee.verificationCode)
  })

  it('differs when the invitee was given another key\'s commitment', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const otherCommitment = await digest(crypto.getRandomValues(new Uint8Array(32)))
    const { request, verificationCode } = await createChannelJoinRequest(channel.channelId, otherCommitment)
    expect(await deriveChannelVerificationCode(request, channel.wrappedChannelAEK, circle)).not.toBe(verificationCode)
  })

  it('throws when the request names a channel the wrapped key is not for', async () => {
    const circle = await circleKey()
    const a = await createChannel(circle)
    const b = await createChannel(circle)
    const { request } = await createChannelJoinRequest(b.channelId, b.aekCommitment)
    await expect(deriveChannelVerificationCode(request, a.wrappedChannelAEK, circle)).rejects.toThrow()
  })
})

// ---------- authorizeChannelJoin ----------

describe('authorizeChannelJoin', () => {
  it('returns a SealedAEK with ciphertext, iv and the sealing ephemeral key', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const sealed = await authorizeChannelJoin(request, channel.wrappedChannelAEK, circle, Date.now())
    expect(sealed.ciphertext).toBeInstanceOf(ArrayBuffer)
    expect(sealed.iv.byteLength).toBe(12)
    expect(sealed.ephemeralPublicKey).not.toEqual(request.ephemeralPublicKey)
  })

  it('accepts a request received just under 5 minutes ago', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const receivedAt = Date.now() - (4 * 60 + 59) * 1000
    await expect(authorizeChannelJoin(request, channel.wrappedChannelAEK, circle, receivedAt)).resolves.toBeDefined()
  })

  it('throws when the request was received more than 5 minutes ago', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const receivedAt = Date.now() - 5 * 60 * 1000 - 100
    await expect(authorizeChannelJoin(request, channel.wrappedChannelAEK, circle, receivedAt)).rejects.toThrow('expired')
  })

  it('throws when the request names a channel the wrapped key is not for', async () => {
    const circle = await circleKey()
    const a = await createChannel(circle)
    const b = await createChannel(circle)
    const { request } = await createChannelJoinRequest(b.channelId, b.aekCommitment)
    await expect(authorizeChannelJoin(request, a.wrappedChannelAEK, circle, Date.now())).rejects.toThrow()
  })

  it('throws under another circle AEK', async () => {
    const channel = await createChannel(await circleKey())
    const { request } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    await expect(authorizeChannelJoin(request, channel.wrappedChannelAEK, await circleKey(), Date.now())).rejects.toThrow()
  })
})

// ---------- finalizeChannelJoin ----------

describe('finalizeChannelJoin', () => {
  it('gives the invitee the channel AEK, and a copy their circle AEK opens', async () => {
    const aliceCircle = await circleKey()
    const bobCircle = await circleKey()
    const channel = await createChannel(aliceCircle)
    const fromAlice = await sealText(channel.channelAEK, 'from alice')

    const bob = await invite(channel, aliceCircle, bobCircle)
    expect(bob.channelAEK.extractable).toBe(false)
    expect(bob.wrappedChannelAEK.byteLength).toBe(60)
    expect(await openText(bob.channelAEK, fromAlice)).toBe('from alice')

    const reopened = await unwrapChannelAEK(channel.channelId, bob.wrappedChannelAEK, bobCircle)
    expect(await openText(reopened, fromAlice)).toBe('from alice')
    await expect(unwrapChannelAEK(channel.channelId, bob.wrappedChannelAEK, aliceCircle)).rejects.toThrow()
  })

  it('throws on a key sealed by someone else, against the channel\'s commitment', async () => {
    const channel = await createChannel(await circleKey())
    const { request, ephemeralPrivateKey } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)

    // The request's ephemeral public key is public: anyone relaying it can seal a key of their own to it.
    const ownKey = crypto.getRandomValues(new Uint8Array(32))
    const sealed = await sealMessage(await importPublicKeyFromJwk(request.ephemeralPublicKey, 'ECDH'), ownKey.buffer as ArrayBuffer)
    await expect(
      finalizeChannelJoin(sealed, ephemeralPrivateKey, await circleKey(), channel.channelId, channel.aekCommitment)
    ).rejects.toThrow('commitment mismatch')
  })

  it('throws with another ephemeral private key', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const other = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const sealed = await authorizeChannelJoin(request, channel.wrappedChannelAEK, circle, Date.now())
    await expect(
      finalizeChannelJoin(sealed, other.ephemeralPrivateKey, await circleKey(), channel.channelId, channel.aekCommitment)
    ).rejects.toThrow()
  })

  it('throws a TypeError for a commitment that is not 32 bytes', async () => {
    const circle = await circleKey()
    const channel = await createChannel(circle)
    const { request, ephemeralPrivateKey } = await createChannelJoinRequest(channel.channelId, channel.aekCommitment)
    const sealed = await authorizeChannelJoin(request, channel.wrappedChannelAEK, circle, Date.now())
    await expect(
      finalizeChannelJoin(sealed, ephemeralPrivateKey, await circleKey(), channel.channelId, new Uint8Array(16))
    ).rejects.toThrow(TypeError)
  })
})

// ---------- across users and their circles ----------

describe('channels across circles', () => {
  const PASSPHRASE = 'correct horse battery staple'

  /** A user's founding device: the circle, and the circle AEK as that device unlocks it. */
  async function foundCircle() {
    const secretKey = crypto.getRandomValues(new Uint8Array(16))
    const { wrappedAEK, aekCommitment } = await initCircle(generateMnemonic(), PASSPHRASE, secretKey)
    const circleAEK = await unwrapKey(PASSPHRASE, wrappedAEK.wrappedKey, wrappedAEK.salt, secretKey)
    return { wrappedAEK, aekCommitment, secretKey, circleAEK }
  }

  let alice: Awaited<ReturnType<typeof foundCircle>>
  let bob: Awaited<ReturnType<typeof foundCircle>>

  beforeAll(async () => {
    alice = await foundCircle()
    bob = await foundCircle()
  })

  it('a device that joins the circle later reads the channels its user is in', async () => {
    // Alice creates a channel and writes to it; Bob's phone is invited.
    const channel = await createChannel(alice.circleAEK)
    const fromAlice = await sealText(channel.channelAEK, 'from alice')
    const bobPhone = await invite(channel, alice.circleAEK, bob.circleAEK)
    expect(await openText(bobPhone.channelAEK, fromAlice)).toBe('from alice')

    // Afterwards, Bob's laptop joins Bob's circle, through the circle's own ceremony.
    const laptopSecretKey = crypto.getRandomValues(new Uint8Array(16))
    const { request, ephemeralPrivateKey } = await createJoinRequest({ name: 'Laptop' })
    const sealedAEK = await authorizeJoin(request, bob.wrappedAEK, PASSPHRASE, bob.secretKey, Date.now())
    const { wrappedAEK } = await finalizeJoin(sealedAEK, ephemeralPrivateKey, PASSPHRASE, laptopSecretKey, bob.aekCommitment)
    const laptopCircleAEK = await unwrapKey(PASSPHRASE, wrappedAEK.wrappedKey, wrappedAEK.salt, laptopSecretKey)

    // With no new invite, the laptop opens Bob's copy of the channel AEK, reads Alice, and writes back.
    const laptopChannelAEK = await unwrapChannelAEK(channel.channelId, bobPhone.wrappedChannelAEK, laptopCircleAEK)
    expect(await openText(laptopChannelAEK, fromAlice)).toBe('from alice')
    const fromLaptop = await sealText(laptopChannelAEK, 'from bob\'s laptop')
    const aliceChannelAEK = await unwrapChannelAEK(channel.channelId, channel.wrappedChannelAEK, alice.circleAEK)
    expect(await openText(aliceChannelAEK, fromLaptop)).toBe('from bob\'s laptop')
  })

  it('a key the server substitutes at an invite changes the invitee\'s code', async () => {
    const channel = await createChannel(alice.circleAEK)

    // The server tells Bob the commitment of a key of its own, then seals that key to Bob's request itself.
    const serverKey = crypto.getRandomValues(new Uint8Array(32))
    const serverCommitment = await digest(serverKey)
    const bobSide = await createChannelJoinRequest(channel.channelId, serverCommitment)
    const relayed: ChannelJoinRequest = { ...bobSide.request }
    const forged = await sealMessage(await importPublicKeyFromJwk(relayed.ephemeralPublicKey, 'ECDH'), serverKey.buffer as ArrayBuffer)

    // The key alone would pass Bob's check, so the codes are what stop it: Alice's comes from her own key.
    await expect(
      finalizeChannelJoin(forged, bobSide.ephemeralPrivateKey, bob.circleAEK, channel.channelId, serverCommitment)
    ).resolves.toBeDefined()
    const aliceCode = await deriveChannelVerificationCode(relayed, channel.wrappedChannelAEK, alice.circleAEK)
    expect(aliceCode).not.toBe(bobSide.verificationCode)
  })
})

// ---------- exports ----------

describe('channel exports from main index', () => {
  it('all channel functions are exported from conseal', () => {
    expect(conseal.createChannel).toBe(createChannel)
    expect(conseal.unwrapChannelAEK).toBe(unwrapChannelAEK)
    expect(conseal.createChannelJoinRequest).toBe(createChannelJoinRequest)
    expect(conseal.deriveChannelVerificationCode).toBe(deriveChannelVerificationCode)
    expect(conseal.authorizeChannelJoin).toBe(authorizeChannelJoin)
    expect(conseal.finalizeChannelJoin).toBe(finalizeChannelJoin)
  })
})
