# fixtures/scopeblind/v1/

ScopeBlind / protect-mcp / VeritasActa interop test vectors.

All artifacts are real Ed25519-signed receipts using RFC 8785 JCS canonicalization. Every artifact in this directory is independently verifiable:

```bash
npx @veritasacta/verify <file.json> --key d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
# exit 0 = valid, exit 1 = tampered, exit 2 = error
```

## Keypair

RFC 8032 Test Vector #1 (well-known, deterministic). Do NOT use in production.

| Field | Value |
|---|---|
| Public key | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |
| kid | `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` |
| Algorithm | Ed25519 |
| Canonicalization | JCS (RFC 8785) |

## Fixture Categories

### 1. Cedar Policy Evaluation (`cedar-policy-evaluation.json`)

Three decision receipts produced by protect-mcp after evaluating Cedar `isAuthorized()` calls:

- **allow** — signed-known agent, `read_database`, policy match
- **deny** — unknown agent, `delete_user`, tier insufficient
- **conditional** — signed-known agent, `write_file`, scope narrowed with conditions

Each receipt carries the Cedar action, principal, and resource expressions alongside the policy digest.

### 2. Receipt Chain (`receipt-chain.json`)

Five-step delegation chain: **PM → analyst → trader → execution → settlement**.

Each receipt carries `parent_receipt_id` pointing to the SHA-256 hash of the previous receipt. A verifier walks the chain backwards checking `ed25519.verify()` at each step. If any link fails, the chain is broken.

```
Step 1: task_delegation    (PM authorizes analysis)
Step 2: analysis_complete  (analyst produces recommendation)
Step 3: trade_preparation  (trader prepares order)
Step 4: execution          (execution fills order on NYSE)
Step 5: settlement         (settlement confirms T+2)
```

### 3. Issuer-Blind Verification (`issuer-blind.json`)

Two vectors demonstrating offline verification without issuer contact:

- **Valid receipt** — verifies with public key only, no network calls
- **Tampered receipt** — one field changed (`decision: allow → deny`), signature correctly rejected

The verifier needs only the receipt JSON and the public key. No DID resolution, no API calls, no trust in any organization.

## Interop Gate Mapping

| Gate | Status | Notes |
|---|---|---|
| identity_gate | `not_applicable` | Issuer-blind by design. Verification does not require DID resolution. |
| delegation_gate | `supported` | `parent_receipt_id` links receipts into a hash chain. |
| wallet_state_gate | `not_applicable` | Receipts are content-addressed, not wallet-addressed. |
| revocation_gate | `not_applicable` | Receipts are immutable signed artifacts. No revocation by design. |
| policy_gate | `supported` | Cedar policy digest in each receipt payload. |

## Structural Divergences from APS/AgentID

These are honest gaps, not vocabulary change requests:

1. **Issuer-blind**: VeritasActa receipts are verifiable without knowing who generated them. The `identity_gate` is structurally `not_applicable` because the verification model does not require identity resolution. This is a design choice, not a limitation.

2. **Content-addressed, not wallet-addressed**: Receipts are identified by their canonical hash. There is no wallet binding. The `wallet_state_gate` is `not_applicable`.

3. **No revocation**: A signed receipt is an immutable fact. "This decision was made" cannot be unsaid. Future decisions can supersede it, but the receipt itself is permanent.

## Regeneration

```bash
cd artifacts/
node generate-interop-fixtures.js > interop-fixtures-scopeblind-v1.json
```
