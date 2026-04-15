# fixtures/aps/v1/

AEOESS Agent Passport System (APS) interop test vectors.

All artifacts are real Ed25519-signed envelopes using RFC 8785 JCS canonicalization. Every signed artifact in this directory is independently verifiable offline:

```bash
# Extract any artifact from the bundle, write to tmp.json, then:
node artifacts/verify-aps-fixture.js tmp.json --key d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
# exit 0 = valid, exit 1 = tampered, exit 2 = verifier error
```

The verifier is zero-dependency (Node stdlib only). Any implementer can reproduce it in ~50 lines.

## Keypair

RFC 8032 Test Vector #1 (well-known, deterministic). Do NOT use in production.

| Field | Value |
|---|---|
| Public key | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |
| kid | `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` |
| Algorithm | Ed25519 |
| Canonicalization | JCS (RFC 8785) |

Same keypair as `fixtures/scopeblind/v1/` — cross-system verification uses one public key.

## Fixture Categories

### 1. Delegation chain receipts (`delegation_chain_receipts`)

Three-step receipt sequence capturing a single action:

```
intent_receipt  → decision_receipt → action_receipt
(agent)           (gateway)           (agent)
```

Each receipt carries `parent_receipt_id` = sha256(jcs(previous signed artifact)). A verifier walks the chain backwards and checks Ed25519 at each step; any broken link invalidates the chain.

### 2. Monotonic narrowing (`monotonic_narrowing`)

The APS core invariant: **authority can only decrease at each transfer point.**

- Parent grants `[read, write, transfer]`
- Child narrows to `[read, write]`
- Grandchild narrows to `[read]`
- Fourth artifact: child attempts to re-grant `[read, write, publish]` — `publish` was never in the parent scope

The invalid-expansion artifact is **correctly Ed25519-signed** by the intermediate delegator. The signature verifies. A compliant APS verifier must still reject it at `delegation_gate` because scope ⊄ parent.scope. This is the interop test for monotonic narrowing: signature validity alone is not sufficient.

### 3. ActionReceipt + offline verification (`action_receipt_offline_verification`)

Two vectors:

- **Valid** — signed, verifies with public key only
- **Tampered** — one field mutated post-sign (`action: read_resource → delete_resource`); signature correctly rejects

No DID resolution, no network, no issuer contact. The artifact plus the public key is all a verifier needs.

### 4. BoundWallet `wallet_ref` (`bound_wallet`)

APS envelope binds an agent DID to an external on-chain wallet. Two chain examples:

- **EVM** — `eip155:1`, CAIP-10 address, `eth_sign` proof-of-control stub
- **Solana** — `mainnet-beta`, `_pending_solana_extension: true` (lifts in SDK 1.43+, where base58 wallet_ref validation lands; fixture shape is forward-compatible)

The APS Ed25519 signature proves the agent claimed the binding. The `external_signature` inside `proof_of_control` is the wallet-side proof (ECDSA for EVM, Ed25519 for Solana) — APS does not re-verify it; chain-native verifiers do.

**Solana caveat:** shape is forward-compatible with APS SDK ≥ 1.43. Envelope signature verifies today. SDK-side `wallet_ref` parser for the Solana variant lands in 1.43.

## Interop Gate Mapping

| Gate | Status | Notes |
|---|---|---|
| `identity_gate` | `supported` | did:aps, did:key, did:web resolution; Ed25519 over JCS-canonical passport |
| `delegation_gate` | `supported` | Monotonic narrowing enforced; scope ⊆ parent.scope required; fixture demonstrates both valid narrowing and invalid expansion |
| `wallet_state_gate` | `partial` | `bound_wallet` envelope with CAIP-10 `wallet_ref` + `proof_of_control`; Solana wallet-ref parser pending SDK 1.43 |
| `revocation_gate` | `partial` | Cascade revocation by issuer signature is implemented in SDK; verifiable revocation-receipt fixtures land in v1.1 |
| `policy_gate` | `supported` | `policy_digest` in `decision_receipt` payload; full policy-eval fixtures land in v1.1 |

## Structural Divergences from ScopeBlind / AgentID

Honest gaps, not vocabulary change requests:

1. **Identity is load-bearing in APS.** ScopeBlind is issuer-blind by design; APS is not. The delegator/delegate DIDs in every delegation artifact carry semantic weight: they determine scope inheritance, cascade revocation reach, and reputation binding. APS's `identity_gate` is therefore `supported` (required), where ScopeBlind's is `not_applicable` (unused).

2. **Monotonic narrowing is an invariant, not a convention.** APS verifiers must check `scope ⊆ parent.scope` at every link of a delegation chain. The `invalid expansion` vector demonstrates: a correctly-signed delegation can still be semantically invalid. This is what ScopeBlind fixtures don't test because scope-narrowing is not part of the ScopeBlind/Cedar model.

3. **Wallets are addressable.** APS supports wallet-addressed receipts via BoundWallet, where ScopeBlind is content-addressed only. `wallet_state_gate` is `supported` in APS, `not_applicable` in ScopeBlind.

4. **Receipts carry identities, not just decisions.** APS `action_receipt.payload.agent` names the agent DID responsible. ScopeBlind receipts are identity-free by policy.

## Regeneration

```bash
cd artifacts/
node generate-aps-fixtures.js
# Writes ../fixtures/aps/v1/interop-fixtures-aps-v1.json
# Re-running produces byte-identical output (deterministic timestamps + nonces).
# Aborts if any artifact fails verification against the test public key.
```

The generator signs with RFC 8032 Test Vector #1's private key, inlined at the top of the script. Both signing and verification use Node stdlib `crypto` (same code path as `agent-passport-system/src/crypto/keys.ts`).
