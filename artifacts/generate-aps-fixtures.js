#!/usr/bin/env node
// Generate APS interop fixture batch v1.
// Deterministic: fixed timestamps, fixed nonces, fixed keypair.
// Re-running this script MUST produce byte-identical output.
//
// Keypair: RFC 8032 Test Vector #1 — well-known, do NOT use in production.

import crypto from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dirname, '..', 'fixtures', 'aps', 'v1', 'interop-fixtures-aps-v1.json')

// ── RFC 8032 Test Vector #1 ──
const PRIV_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const PUB_HEX  = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const KID      = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'

// ── Ed25519 (matches SDK src/crypto/keys.ts exactly) ──
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  return out
}
function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
}
function sign(message, privHex) {
  const priv = hexToBytes(privHex)
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(priv)])
  const key = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  return bytesToHex(new Uint8Array(crypto.sign(null, Buffer.from(message, 'utf8'), key)))
}
function verify(message, sigHex, pubHex) {
  try {
    const pub = hexToBytes(pubHex)
    const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub)])
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(hexToBytes(sigHex)))
  } catch { return false }
}

// ── JCS (RFC 8785) — preserves null, sorts keys by code point ──
function jcs(v) {
  if (v === null || v === undefined) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') {
    if (!isFinite(v)) throw new Error('JCS: no Infinity/NaN')
    return JSON.stringify(v)
  }
  if (typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort()
    return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
  }
  throw new Error(`JCS: unsupported ${typeof v}`)
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex')
}

// ── Signed-envelope helper ──
// Mirrors Tom's shape: { v, type, algorithm, kid, issuer, issued_at, payload, signature }
// Signature covers JCS(canonical envelope WITHOUT signature field).
function makeArtifact({ type, issuer, issued_at, payload }) {
  const unsigned = { v: 2, type, algorithm: 'ed25519', kid, issuer, issued_at, payload }
  const sigHex = sign(jcs(unsigned), PRIV_HEX)
  const artifact = { ...unsigned, signature: sigHex }
  // Immediate verification — abort if broken
  if (!verify(jcs(unsigned), sigHex, PUB_HEX)) {
    throw new Error(`Signature verification failed for ${type} / ${issued_at}`)
  }
  return { artifact, hash: sha256hex(jcs(artifact)) }
}

const kid = KID

// ══════════════════════════════════════════════════════════
// Category 1a: Delegation chain receipt sequence
// intent → decision → execution, each linked by parent_receipt_id
// ══════════════════════════════════════════════════════════
const intent = makeArtifact({
  type: 'intent_receipt',
  issuer: 'did:aps:z6MkTestPrincipal001',
  issued_at: '2026-04-01T09:00:00Z',
  payload: {
    step: 'intent_declared',
    agent: 'did:aps:z6MkTestAgent042',
    intent: 'transfer_funds',
    scope_requested: ['transfer:usd:≤100'],
    request_id: 'req_delegchain_001',
    parent_receipt_id: null
  }
})
const decision = makeArtifact({
  type: 'decision_receipt',
  issuer: 'did:aps:z6MkGatewayAeoess',
  issued_at: '2026-04-01T09:00:01Z',
  payload: {
    step: 'gateway_decision',
    decision: 'allow',
    agent: 'did:aps:z6MkTestAgent042',
    scope_granted: ['transfer:usd:≤100'],
    active_delegation: 'del_001',
    policy_digest: 'sha256:' + sha256hex('aps-policy-v1.42'),
    request_id: 'req_delegchain_001',
    parent_receipt_id: intent.hash
  }
})
const execution = makeArtifact({
  type: 'action_receipt',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T09:00:02Z',
  payload: {
    step: 'action_committed',
    agent: 'did:aps:z6MkTestAgent042',
    action: 'transfer_funds',
    amount: { value: 50, currency: 'USD' },
    counterparty: 'did:aps:z6MkCounterparty007',
    action_ref: 'act_' + sha256hex('req_delegchain_001|transfer|50USD').slice(0, 16),
    request_id: 'req_delegchain_001',
    parent_receipt_id: decision.hash
  }
})

// ══════════════════════════════════════════════════════════
// Category 1b: Monotonic narrowing
// parent broad → child narrower → grandchild narrowest, + invalid expansion
// ══════════════════════════════════════════════════════════
const parentDel = makeArtifact({
  type: 'delegation',
  issuer: 'did:aps:z6MkTestPrincipal001',
  issued_at: '2026-04-01T10:00:00Z',
  payload: {
    delegator: 'did:aps:z6MkTestPrincipal001',
    delegate: 'did:aps:z6MkTestAgent042',
    scope: ['read', 'write', 'transfer'],
    spend_limit: { amount: 1000, currency: 'USD', period: 'day' },
    not_before: '2026-04-01T00:00:00Z',
    not_after: '2026-05-01T00:00:00Z',
    nonce: 'mn-parent-001',
    parent: null
  }
})
const childDel = makeArtifact({
  type: 'delegation',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T10:00:01Z',
  payload: {
    delegator: 'did:aps:z6MkTestAgent042',
    delegate: 'did:aps:z6MkTestAgent108',
    scope: ['read', 'write'],
    spend_limit: { amount: 500, currency: 'USD', period: 'day' },
    not_before: '2026-04-01T00:00:00Z',
    not_after: '2026-05-01T00:00:00Z',
    nonce: 'mn-child-001',
    parent: parentDel.hash
  }
})
const grandchildDel = makeArtifact({
  type: 'delegation',
  issuer: 'did:aps:z6MkTestAgent108',
  issued_at: '2026-04-01T10:00:02Z',
  payload: {
    delegator: 'did:aps:z6MkTestAgent108',
    delegate: 'did:aps:z6MkTestAgent211',
    scope: ['read'],
    spend_limit: { amount: 100, currency: 'USD', period: 'day' },
    not_before: '2026-04-01T00:00:00Z',
    not_after: '2026-05-01T00:00:00Z',
    nonce: 'mn-grandchild-001',
    parent: childDel.hash
  }
})
// Invalid expansion — signed correctly, but scope claims rights parent never granted.
// Must be rejected at delegation_gate by any compliant verifier.
const invalidExpansion = makeArtifact({
  type: 'delegation',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T10:00:03Z',
  payload: {
    delegator: 'did:aps:z6MkTestAgent042',
    delegate: 'did:aps:z6MkTestAgent911',
    scope: ['read', 'write', 'publish'], // 'publish' not in parent scope
    spend_limit: { amount: 500, currency: 'USD', period: 'day' },
    not_before: '2026-04-01T00:00:00Z',
    not_after: '2026-05-01T00:00:00Z',
    nonce: 'mn-invalid-001',
    parent: parentDel.hash
  }
})

// ══════════════════════════════════════════════════════════
// Category 1c: ActionReceipt + tamper detection
// ══════════════════════════════════════════════════════════
const validAction = makeArtifact({
  type: 'action_receipt',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T11:00:00Z',
  payload: {
    agent: 'did:aps:z6MkTestAgent042',
    action: 'read_resource',
    resource: 'urn:aps:resource:market-data-aapl',
    action_ref: 'act_' + sha256hex('read|market-data-aapl|2026-04-01T11:00:00Z').slice(0, 16),
    request_id: 'req_action_001',
    parent_receipt_id: null
  }
})
// Tampered: copy valid artifact, flip one payload field. Signature MUST reject.
const tamperedAction = JSON.parse(JSON.stringify(validAction.artifact))
tamperedAction.payload.action = 'delete_resource'
const tamperedUnsigned = { ...tamperedAction }
delete tamperedUnsigned.signature
const tamperedVerifies = verify(jcs(tamperedUnsigned), tamperedAction.signature, PUB_HEX)
if (tamperedVerifies) throw new Error('Tampered artifact unexpectedly verified — aborting')

// ══════════════════════════════════════════════════════════
// Category 1d: BoundWallet wallet_ref
// ══════════════════════════════════════════════════════════
const evmWallet = makeArtifact({
  type: 'bound_wallet',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T12:00:00Z',
  payload: {
    agent: 'did:aps:z6MkTestAgent042',
    wallet_ref: {
      chain: 'evm',
      chain_id: 1,
      address: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
      caip10: 'eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7'
    },
    binding_nonce: 'bw-evm-001',
    proof_of_control: {
      method: 'signed_challenge',
      challenge: 'aps-bind-2026-04-01-evm-001',
      // Placeholder external signature — the wallet-side proof, not the SDK's Ed25519 sig.
      // Real integrations would include the EVM ECDSA signature here.
      external_signature: '0x' + '00'.repeat(65),
      external_signature_format: 'eth_sign'
    }
  }
})
const solanaWallet = makeArtifact({
  type: 'bound_wallet',
  issuer: 'did:aps:z6MkTestAgent042',
  issued_at: '2026-04-01T12:00:01Z',
  payload: {
    agent: 'did:aps:z6MkTestAgent042',
    wallet_ref: {
      chain: 'solana',
      cluster: 'mainnet-beta',
      address: 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy',
      caip10: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy'
    },
    binding_nonce: 'bw-sol-001',
    proof_of_control: {
      method: 'signed_challenge',
      challenge: 'aps-bind-2026-04-01-sol-001',
      external_signature: '0'.repeat(128),
      external_signature_format: 'ed25519_solana'
    }
  }
})

// ══════════════════════════════════════════════════════════
// Compose output
// ══════════════════════════════════════════════════════════
const GENERATED_AT = '2026-04-15T00:00:00Z' // deterministic

const verifyCmd = (name) =>
  `node artifacts/verify-aps-fixture.js ${name} --key ${PUB_HEX}`

const out = {
  _meta: {
    system: 'AEOESS Agent Passport System (APS)',
    version: '1.42.0',
    generated_at: GENERATED_AT,
    keypair: {
      public_key: PUB_HEX,
      kid: KID,
      jwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        kid: KID,
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        use: 'sig'
      },
      note: 'RFC 8032 Test Vector #1 — do NOT use in production'
    },
    canonicalization: 'JCS (RFC 8785) — JSON Canonicalization Scheme',
    signing_algorithm: 'Ed25519 (RFC 8032)',
    envelope_format: 'APS signed artifact envelope (v2)',
    verification: {
      cli: 'node artifacts/verify-aps-fixture.js <artifact-file.json> --key <public_key_hex>',
      sdk: 'agent-passport-system ≥ 1.42.0 — import { canonicalizeJCS } and verify via crypto.verify',
      exit_codes: {
        0: 'signature valid — proven authentic',
        1: 'signature invalid — proven tampered',
        2: 'verifier error — malformed input or missing key'
      }
    },
    interop_gates: {
      identity_gate: 'supported — did:aps + did:key + did:web resolution; Ed25519 signature over JCS-canonical passport',
      delegation_gate: 'supported — monotonic narrowing enforced; parent field links chain; scope ⊆ parent.scope required',
      wallet_state_gate: 'partial — bound_wallet envelope ships with wallet_ref + proof_of_control; Solana extension lands in SDK ≥ 1.43',
      revocation_gate: 'supported — cascade revocation by issuer signature; revocation receipts not in this v1 batch (see v1.1)',
      policy_gate: 'supported — policy_digest in decision_receipt payload; full policy-eval fixtures in v1.1'
    },
    pending: {
      solana_bound_wallet: 'SDK extension targeted for 1.43.0; shape included here is forward-compatible but not yet SDK-validated'
    }
  },

  delegation_chain_receipts: {
    description: 'Three-step receipt sequence: intent → decision → execution. Each receipt links to the previous via parent_receipt_id (sha256 over JCS-canonical form of the full signed artifact).',
    canonicalization: 'JCS (RFC 8785)',
    algorithm: 'Ed25519',
    verification_command: 'Walk execution → decision → intent; verify Ed25519 at each step; confirm parent_receipt_id matches sha256(jcs(previous_artifact)).',
    vectors: [
      { name: 'Step 1: intent_receipt (agent declares intent)', expected_result: 'valid', verification_command: verifyCmd('step-1-intent.json'), ...intent },
      { name: 'Step 2: decision_receipt (gateway approves under active scope)', expected_result: 'valid', verification_command: verifyCmd('step-2-decision.json'), ...decision },
      { name: 'Step 3: action_receipt (action committed)', expected_result: 'valid', verification_command: verifyCmd('step-3-execution.json'), ...execution }
    ]
  },

  monotonic_narrowing: {
    description: 'Authority can only decrease across a delegation chain. Parent grants [read, write, transfer]; child narrows to [read, write]; grandchild narrows to [read]. A fourth artifact demonstrates an attempted scope expansion — it is correctly Ed25519-signed by the intermediate delegator, but its scope claims `publish`, which the parent never granted. Any compliant verifier MUST reject it at delegation_gate despite the valid signature.',
    canonicalization: 'JCS (RFC 8785)',
    algorithm: 'Ed25519',
    vectors: [
      { name: 'Parent delegation (broad: read, write, transfer)', expected_result: 'valid', verification_command: verifyCmd('mn-parent.json'), ...parentDel },
      { name: 'Child delegation (narrowed: read, write)', expected_result: 'valid', verification_command: verifyCmd('mn-child.json'), ...childDel },
      { name: 'Grandchild delegation (narrowed: read)', expected_result: 'valid', verification_command: verifyCmd('mn-grandchild.json'), ...grandchildDel },
      {
        name: 'Invalid expansion attempt (child claims publish — parent never granted)',
        expected_result: 'signature_valid_but_delegation_gate_must_reject',
        delegation_gate_reason: 'scope contains "publish" which is not a subset of parent.scope [read, write, transfer]',
        verification_command: verifyCmd('mn-invalid-expansion.json'),
        ...invalidExpansion
      }
    ]
  },

  action_receipt_offline_verification: {
    description: 'Offline verification demo. One valid ActionReceipt signed with the test keypair and one tampered copy where `action` was flipped from read_resource to delete_resource. Ed25519.verify() rejects the tampered artifact using only the public key — no network, no issuer contact.',
    canonicalization: 'JCS (RFC 8785)',
    algorithm: 'Ed25519',
    vectors: [
      { name: 'Valid action receipt', expected_result: 'valid', verification_command: verifyCmd('action-valid.json'), ...validAction },
      {
        name: 'Tampered action receipt (action field mutated post-sign)',
        expected_result: 'invalid',
        tamper_description: 'payload.action changed from "read_resource" to "delete_resource" after signing; signature over original JCS-canonical form no longer verifies',
        verification_command: verifyCmd('action-tampered.json'),
        artifact: tamperedAction,
        hash: sha256hex(jcs(tamperedAction))
      }
    ]
  },

  bound_wallet: {
    description: 'BoundWallet envelopes linking an APS agent DID to an external on-chain wallet. Each carries wallet_ref (CAIP-10 plus chain-native fields) and proof_of_control. The APS signature binds the agent identity; the external_signature inside proof_of_control binds the wallet side (not re-verified by APS).',
    canonicalization: 'JCS (RFC 8785)',
    algorithm: 'Ed25519 (APS envelope); external signatures are chain-native',
    vectors: [
      { name: 'EVM wallet binding (eip155:1)', expected_result: 'valid', verification_command: verifyCmd('wallet-evm.json'), ...evmWallet },
      {
        name: 'Solana wallet binding (mainnet-beta)',
        expected_result: 'valid',
        _pending_solana_extension: true,
        note: 'Shape is forward-compatible with APS SDK ≥ 1.43 Solana extension. APS envelope signature verifies today; SDK-side wallet-ref parser lands in 1.43.',
        verification_command: verifyCmd('wallet-solana.json'),
        ...solanaWallet
      }
    ]
  }
}

writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n')
console.error(`Wrote ${OUT}`)

// ── Final pass: re-verify every signed artifact from the emitted JSON ──
function walk(node, path, found) {
  if (!node || typeof node !== 'object') return
  if (node.artifact && node.artifact.signature && node.artifact.algorithm === 'ed25519') {
    found.push({ path, vector: node })
  }
  for (const k of Object.keys(node)) walk(node[k], path + '.' + k, found)
}
const allArtifacts = []
walk(out, '$', allArtifacts)
let verifiedCount = 0
let tamperRejectedCount = 0
for (const { path, vector } of allArtifacts) {
  const artifact = vector.artifact
  const { signature, ...unsigned } = artifact
  const ok = verify(jcs(unsigned), signature, PUB_HEX)
  const isTamper = vector.expected_result === 'invalid'
  if (isTamper) {
    if (ok) throw new Error(`Tampered artifact at ${path} unexpectedly verified`)
    tamperRejectedCount++
  } else {
    if (!ok) throw new Error(`Verification failed at ${path}`)
    verifiedCount++
  }
}
console.error(`Verified ${verifiedCount} artifacts; ${tamperRejectedCount} tampered correctly rejected; total ${allArtifacts.length}.`)
