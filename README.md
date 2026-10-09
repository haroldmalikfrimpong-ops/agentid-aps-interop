# AgentID + APS Interop Test Vectors

Joint interop test fixtures for the **AgentID identity** + **APS authorization** + **governance receipt** chain.

## Purpose

Verify the complete audit chain:
1. **Identity** (AgentID) — "Who is this agent?"
2. **Authorization** (APS) — "What may this agent do?"
3. **Receipt** (APS) — "What did it actually do?"
4. **Security posture** (AgentGraph) — "Is the agent's code safe to run?"

Independent implementations, one shared fixture set, deterministic pass/fail.

## Structure

```
vector.schema.json      # JSON Schema (Draft 2020-12) — contract for all v1+ test vectors
fixtures/
  agentid/                          # AgentID identity verification artifacts and vectors
    registration.json               # Agent registration payload (artifact, pre-v1)
    ed25519-binding.json            # Ed25519 key binding + certificate (artifact, pre-v1)
    trust-header.json               # Signed trust-header JWT (artifact, pre-v1)
    did-document.json               # W3C DID Document (artifact, pre-v1)
    verify-response.json            # Full verification response (artifact, pre-v1)
    v1/                             # Schema-validated test vectors
      happy-path.json               # Identity passes all gates → permit
      revoked-key.json              # Ed25519 key revoked → key_lifecycle gate fails → deny
      stale-cert.json               # Certificate expired → identity gate fails → deny
  aps/                              # APS authorization fixtures (contributed by @aeoess)
    v1/
      happy-path-both-valid.json    # Identity + delegation both pass → permit
      agentid-valid-aps-revoked.json # Identity passes, delegation revoked → deny
      aps-valid-agentid-stale.json  # Delegation valid, identity stale → conditional
  agentgraph/                       # AgentGraph security-scan fixtures (contributed by @kenneives)
    v1/
      happy-path.json               # All three security gates pass → permit
      critical-deps-fail.json       # dependency_audit fails (2 critical CVEs) → deny
      secret-leaked.json            # secret_scan fails (committed API key) → deny
  composed/                         # (planned) Multi-attestation envelopes carrying two or three signals
    v1/
  cross-chain/
    identity-to-receipt.json        # Full chain test (pre-v1)
  action-ref/
    v2/                             # action_ref v1 (frozen, raw-concat, tuple-ambiguous) next to v2 (JCS-framed) — vectors + collision pairs
composed/
  v2/                               # three-signal envelopes; AgentAvow + AgentID slots production-signed, APS structural
tools/
  action_ref_v2.py                  # recompute + assert every action-ref vector
crosswalk/
  agentid-to-aps.yaml               # Field-name mapping between vocabularies (v0.1)
```

### What's new — `interop-freeze-2026-10-06`

- **AgentID slot signed in `composed/v2`** with the production key `agentid-2026-03`
  (`did:web:getagentid.dev#agentid-2026-03`); `composed/v2/jwks.json` now carries the
  AgentAvow and AgentID production public keys; `composed/v2/verify.py` → 84 checks incl.
  AgentID tamper rejection. See [composed/v2/README.md](composed/v2/README.md).
- **`fixtures/action-ref/v2`**: the raw-concat `action_ref` (v1, frozen as pinned in
  `interop-freeze-2026-10-01` and preaction-governance-conformance#9) is tuple-ambiguous;
  v2 = `sha256(JCS({agent_id, action_type, scope, timestamp_ms}))` is framed. Positive
  (pinned PR #9 tuple), two collision pairs, one control. See
  [fixtures/action-ref/v2/README.md](fixtures/action-ref/v2/README.md).

Verify everything added in this freeze:

```bash
pip install jcs cryptography
PYTHONUTF8=1 python3 composed/v2/verify.py            # 3 fixtures, 84/84
PYTHONUTF8=1 python3 composed/v2/generate.py --check  # reproducible, both JWS verify
python3 tools/action_ref_v2.py                        # 4 vectors, 30/30
```

### Optional receipt-graph policy fixtures

[Issue #12](https://github.com/haroldmalikfrimpong-ops/agentid-aps-interop/issues/12)
has five [adversarial vectors](fixtures/adversarial/v1/README.md) and an
[offline four-signal composition](composed/adversarial/v1/README.md): closed ring,
hub and spokes, replayed receipts, a ring with outside evidence, and a
sponsor-backed passing control. The opt-in graph signal limits a consumer's
synthetic exposure policy after the existing identity, authorization, and
security gates. It does not add a provenance gate or change the frozen v1/v2
profiles. Root independence, available budgets, and receipt truth are explicit
fixture assumptions, not facts inferred from signatures.

```bash
pip install jcs jsonschema
python3 composed/adversarial/v1/verify.py
python3 -m unittest discover -s composed/adversarial/v1 -p 'test_*.py' -v
```

### Schema validation

All v1+ fixtures validate against `vector.schema.json` (Draft 2020-12). Quick check:

```bash
pip install jsonschema
python -c "
import json
from jsonschema import Draft202012Validator
schema = json.load(open('vector.schema.json'))
validator = Draft202012Validator(schema)
for path in ['fixtures/agentid/v1/happy-path.json', 'fixtures/agentid/v1/revoked-key.json', 'fixtures/agentid/v1/stale-cert.json']:
    fixture = json.load(open(path))
    errors = list(validator.iter_errors(fixture))
    print(f'{path}: {\"PASS\" if not errors else \"FAIL\"}')"
```

Each v1 fixture is **structural-shape** (not yet cryptographically verifiable). The schema's `signed_form` block is optional in v1 and REQUIRED in v2 — the v2 batch will add real JWS bytes signed against the test agent's deterministic seed, and `signed_form.public_key` for offline verification.

### Per-gate failure reporting

Each fixture's `expected_result` declares which gates the verifier should evaluate (`identity_gate`, `delegation_gate`, `key_lifecycle_gate`) and which gate was decisive (`decisive_gate`). The composition rule is **AND across all evaluated gates** — a single failure produces a deny without collapsing the per-gate diagnosis into one confidence score. Consumers reading the fixture know exactly which gate they should expect to see fail.

## Test Agent

All fixtures reference a **test-only agent** with deterministic keys generated from a known seed. No production credentials.

- Agent ID: `agent_interop_test_001`
- DID: `did:web:getagentid.dev:agent:agent_interop_test_001`
- Ed25519 seed: `0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- Ed25519 public key: derived deterministically from seed
- Trust Level: L2 (Verified)

## Verification

Each fixture includes:
- Input data
- Expected output
- Cryptographic signatures (verifiable with the public key above)

Implementors run their verification path against the fixtures and report pass/fail.

## Contributors

- **AgentID** ([@haroldmalikfrimpong-ops](https://github.com/haroldmalikfrimpong-ops)) — Identity verification fixtures
- **APS** ([@aeoess](https://github.com/aeoess)) — Authorization + governance receipt fixtures
- **AgentGraph** ([@kenneives](https://github.com/kenneives)) — Security-scan fixtures (third signal)

## Context

Established via [A2A #1672](https://github.com/a2aproject/A2A/issues/1672) — cross-algorithm verification confirmed 3/3 (valid Ed25519, algorithm mismatch rejection, bad signature rejection).
