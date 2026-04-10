# AgentID + APS Interop Test Vectors

Joint interop test fixtures for the **AgentID identity** + **APS authorization** + **governance receipt** chain.

## Purpose

Verify the complete audit chain:
1. **Identity** (AgentID) — "Who is this agent?"
2. **Authorization** (APS) — "What may this agent do?"
3. **Receipt** (APS) — "What did it actually do?"

Two independent implementations, one shared fixture set, deterministic pass/fail.

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
  composed/                         # (planned) Multi-attestation envelopes carrying both
    v1/
  cross-chain/
    identity-to-receipt.json        # Full chain test (pre-v1)
crosswalk/
  agentid-to-aps.yaml               # Field-name mapping between vocabularies (v0.1)
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

## Context

Established via [A2A #1672](https://github.com/a2aproject/A2A/issues/1672) — cross-algorithm verification confirmed 3/3 (valid Ed25519, algorithm mismatch rejection, bad signature rejection).
