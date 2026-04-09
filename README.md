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
fixtures/
  agentid/           # AgentID credential fixtures
    registration.json    # Agent registration payload
    ed25519-binding.json # Ed25519 key binding + certificate
    trust-header.json    # Signed trust-header JWT (EdDSA)
    did-document.json    # W3C DID Document
    verify-response.json # Full verification response
  aps/               # APS authorization fixtures (contributed by @aeoess)
    delegation.json      # Delegation scope evaluation
    receipt.json         # Governance receipt referencing AgentID credential hash
  cross-chain/       # End-to-end test vectors
    identity-to-receipt.json  # Full chain test
```

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
