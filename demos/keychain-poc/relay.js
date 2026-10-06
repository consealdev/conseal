/**
 * Keychain PoC — Relay Server
 *
 * A dumb HTTP store with no cryptographic capability. It stores blobs by key
 * and returns them on request. It never receives a passphrase, a raw key, or
 * plaintext. Watch its log to verify that claim throughout the demo.
 *
 * POST /store/:key   — store a JSON blob
 * GET  /fetch/:key   — retrieve a stored blob
 */

import { createServer } from 'node:http'

const store = new Map()

const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json')
    const [, action, key] = req.url.split('/')

    if (req.method === 'POST' && action === 'store' && key) {
        let body = ''
        req.on('data', chunk => { body += chunk })
        req.on('end', () => {
            try {
                const value = JSON.parse(body)
                store.set(key, value)
                const bytes = Buffer.byteLength(body)
                console.log(`[relay] POST /store/${key}  — ${bytes} bytes stored (relay cannot read this)`)
                res.end(JSON.stringify({ ok: true }))
            } catch {
                res.statusCode = 400
                res.end(JSON.stringify({ error: 'invalid JSON' }))
            }
        })
        return
    }

    if (req.method === 'GET' && action === 'fetch' && key) {
        const value = store.get(key)
        if (!value) {
            res.statusCode = 404
            res.end(JSON.stringify({ error: `not found: ${key}` }))
        } else {
            res.end(JSON.stringify(value))
        }
        return
    }

    res.statusCode = 400
    res.end(JSON.stringify({ error: 'use POST /store/:key or GET /fetch/:key' }))
})

server.listen(4400, () => {
    console.log('Relay listening on http://localhost:4400')
    console.log('This server is a structural relay — it stores blobs and cannot read them.')
    console.log('Watch the log: you will never see a passphrase, a key, or plaintext.\n')
})
