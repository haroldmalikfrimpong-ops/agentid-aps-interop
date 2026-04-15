#!/usr/bin/env node
// Standalone APS fixture verifier. Zero deps.
// Usage: node verify-aps-fixture.js <artifact.json> --key <public_key_hex>
// Exit 0 = valid, 1 = invalid, 2 = verifier error.
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'

function hexToBytes(h) {
  const o = new Uint8Array(h.length / 2)
  for (let i = 0; i < h.length; i += 2) o[i / 2] = parseInt(h.slice(i, i + 2), 16)
  return o
}
function jcs(v) {
  if (v === null || v === undefined) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') { if (!isFinite(v)) throw new Error('JCS: no Infinity/NaN'); return JSON.stringify(v) }
  if (typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort()
    return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
  }
  throw new Error(`JCS: unsupported ${typeof v}`)
}

try {
  const [,, file, flag, keyHex] = process.argv
  if (!file || flag !== '--key' || !keyHex) {
    console.error('Usage: verify-aps-fixture.js <artifact.json> --key <public_key_hex>')
    process.exit(2)
  }
  const artifact = JSON.parse(readFileSync(file, 'utf8'))
  if (!artifact || !artifact.signature) { console.error('No signature in artifact'); process.exit(2) }
  const { signature, ...unsigned } = artifact
  const pub = hexToBytes(keyHex)
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub)])
  const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
  const ok = crypto.verify(null, Buffer.from(jcs(unsigned), 'utf8'), key, Buffer.from(hexToBytes(signature)))
  console.log(ok ? 'VALID' : 'INVALID')
  process.exit(ok ? 0 : 1)
} catch (e) {
  console.error('error:', e.message)
  process.exit(2)
}
