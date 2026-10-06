# composed/v2/ — AgentAvow + AgentID slots signed, lockstep in progress

composed-v2 is the signed form of [composed-v1](../v1/README.md). It carries the same
three-signal composition (AgentID + APS + AgentGraph/AgentAvow under one subject DID) with
**two slots signed by their issuers' production keys**: the AgentAvow static_analysis slot
(#11) and the AgentID identity slot (tag `interop-freeze-2026-10-06`). The APS slot rides
**structural (unsigned)** until aeoess signs it. That is what lockstep means here: **each
issuer signs the slot it owns.** No slot in this directory is signed with a stand-in key.

This directory is an addition. composed/v1 is untouched and still passes its checks; the
repo convention is versioned directories (`composed/v1`, `fixtures/*/v1`), so v2 lands
alongside rather than mutating v1 fixture bytes.

Source thread:
[#5](https://github.com/haroldmalikfrimpong-ops/agentid-aps-interop/issues/5) — "v1
structural now, v2 signed in lockstep across all three slots."

## Rebrand note (AgentGraph is now AgentAvow)

The AgentGraph product is now **AgentAvow** (agentavow.com). No machine string moves: the
signing `kid` stays `agentgraph-security-v1`, the issuer stays `did:web:agentgraph.co`, and
`/.well-known/agent-trust.json` / `/.well-known/jwks.json` serve byte-identical at
agentgraph.co and agentavow.com (GitHub 301s old repo/commit refs). The signed bytes here
are unchanged by the rename.

## Slot status in v2

| Slot | v2 version | Signed? | Signer |
|------|-----------|---------|--------|
| `agentgraph` (static_analysis) | `agentgraph-scan-v1-signed` | **yes** — compact JWS, production key | AgentAvow (this PR) |
| `aps` (authorization) | `aps-v2-structural` | no — structural | aeoess signs in follow-up |
| `agentid` (identity) | `agentid-identity-v1-signed` | **yes** — compact JWS, production key `agentid-2026-03` | AgentID (`interop-freeze-2026-10-06`) |

The AgentID slot is also **shape-aligned** per issue #5 item (b): the v1 fixtures shipped
`version:"1.1.0"` + a `did` field while the declared slot shape uses `subject_did`. v2
replaces `did` with `subject_did` and moves the version to
`agentid-identity-v1-structural`, so every slot speaks one subject vocabulary. Aligning the
shape needs no key; it happens in this pass so the slot bytes are not churned twice.

## The AgentAvow signature is production, live-JWKS-verifiable

`slots.agentgraph.signature` is a compact JWS (RFC 7515, EdDSA) produced by the product's
real `src/attestation/composed_slot.sign_slot_v2` over `src/signing.py`, signed with the
**production key** inside the AgentAvow backend. It verifies against the live
[`https://agentgraph.co/.well-known/jwks.json`](https://agentgraph.co/.well-known/jwks.json)
entry `agentgraph-security-v1`
(`x = JwovTLVbpgk85zlMNruTiLzp85dAucsZWngs8NisBFg`). [`jwks.json`](jwks.json) in this
directory contains that one production public key, copied verbatim from the live endpoint,
as the offline trust anchor. This is not a test key: a third party can fetch the live JWKS
and verify the fixture signature against it.

The signed preimage is the v1 *structural* AgentAvow slot (JCS-canonical); the emitted slot
relabels version to `agentgraph-scan-v1-signed` and attaches the JWS in `signature` plus
`signer_key_id`. `verify.py` checks the Ed25519 signature, re-binds the JWS payload to the
recomputed structural slot, and asserts the legacy canonicalizer equals RFC 8785 JCS for
this content (so the `jcs-rfc8785+sha256` label holds).

The production private key is **server-side only and never committed**, so `generate.py`
cannot re-sign locally. The two distinct production JWS strings are embedded in
`generate.py` as data (keyed by each slot's `evidence_hash`); both `generate.py` and
`verify.py` assert each JWS verifies under the AgentAvow public key and binds to the
regenerated structural slot. The structural content is fully reproducible from source; the
signature is verified, not regenerated. `--check` therefore proves byte-for-byte
reproducibility of the fixtures and cryptographic validity of the committed signature.

## The AgentID signature is production, live-JWKS-verifiable

`slots.agentid.signature` is a compact JWS (RFC 7515, EdDSA; header
`{"alg":"EdDSA","kid":"agentid-2026-03"}`) signed by the AgentID issuer with its production
Ed25519 key. It verifies against the live
[`https://getagentid.dev/.well-known/jwks.json`](https://getagentid.dev/.well-known/jwks.json)
entry `agentid-2026-03` (`x = xdpmjfq2DX4d6yML7QjaSkYB2h9Dm3phwts5gkAPBp8`), which is also
`did:web:getagentid.dev#agentid-2026-03` in the issuer's
[`/.well-known/did.json`](https://getagentid.dev/.well-known/did.json). `jwks.json` carries that
public key verbatim as the offline trust anchor, next to the AgentAvow key.

The signed preimage is **RFC 8785 JCS of the structural AgentID slot** (`version:
agentid-identity-v1-structural`, nulls kept — pure JCS, no normaliser); the emitted slot
relabels `version` to `agentid-identity-v1-signed` and attaches `signature` +
`signer_key_id: did:web:getagentid.dev#agentid-2026-03`. All three fixtures carry the same
structural AgentID slot (`agent_interop_test_001`, L2, certificate valid, key active), hence one
JWS. The subject `did:web:getagentid.dev:agent:agent_interop_test_001` resolves live.

As with the AgentAvow slot, the private key is server-side only. The JWS is produced by the
issuer with [`sign_agentid_slot.py`](sign_agentid_slot.py) (seed from the environment, never on
disk, refuses to sign unless the derived key equals the live `agentid-2026-03`), embedded in
`generate.py` as data keyed by `sha256(JCS(structural slot))`, and **verified, not regenerated**
by both `generate.py --check` and `verify.py`.

## Reproducing the fixtures

```
pip install jcs cryptography
python3 composed/v2/generate.py          # rewrite fixtures + jwks.json
python3 composed/v2/generate.py --check  # assert committed files match + AgentAvow JWS verifies, exit 1 on drift
```

## Verifying

```
pip install jcs cryptography
python3 composed/v2/verify.py
```

Expected on a clean tree: 3 fixtures, 84 checks, all pass, exit 0. Per fixture the verifier
runs every structural check composed/v1 ran (composition_version, subject-DID binding, slot
versions, APS `delegation_chain_root` recompute, JCS-canonicalizability, composite decision
+ `failing_slots`) plus:

- `slots.aps` carries **no** signature material (structural in v2).
- `slots.agentgraph` Ed25519/JWS signature verifies against the live AgentAvow key, and the
  JWS payload re-binds to the slot content.
- `slots.agentid` Ed25519/JWS signature verifies against the live AgentID key
  (`kid agentid-2026-03`), the payload re-binds to `JCS(structural slot)`, the signed
  `subject_did` equals the envelope subject, and `signer_key_id` is
  `did:web:getagentid.dev#agentid-2026-03`.
- **Negative self-tests:** each signed slot is tampered in memory and verification MUST
  fail — AgentAvow: gate-grade flip, signature flip; AgentID: `trust_level` flip,
  `key_status` flip, signature flip, and re-attribution to a foreign `kid`. These rows prove
  the signature checks have teeth without adding fail-fixtures to the pass scan.

## The three fixtures

| Fixture | Scenario | Expected |
|---------|----------|----------|
| `agent_interop_test_001/happy-path.json` | all three signals pass | permit, `all_passed` |
| `agent_interop_test_001/aps-revoked-delegation.json` | APS hop-0 revoked | deny, decisive `aps` |
| `agent_interop_test_001/agentgraph-secret-leaked.json` | AgentAvow `secret_scan` grade F | deny, decisive `agentgraph` |

The AgentAvow signature is orthogonal to the composite verdict: the grade-F-but-signed
AgentAvow slot in the secret-leaked fixture verifies cryptographically yet still denies
under the naive all-must-pass rule — the deny comes from the slot's native state, not a bad
signature.

The composed-v1 `happy-path-with-{concordia,hive,jep}` variants are out of scope here (they
carry other issuers' slots); v2 covers the three core gating slots this issue is about.

## Contributors and next steps

- **Kenne (kenneives)** — AgentAvow slot signing (production key), AgentID slot shape
  alignment, v2 generator + verifier, this README.
- **aeoess** — signs the APS slot in the coordinated lockstep follow-up.
- **Harold (haroldmalikfrimpong-ops)** — AgentID slot signing (production key
  `agentid-2026-03`), `sign_agentid_slot.py`, AgentID verification rows + negative
  self-tests, this update (`interop-freeze-2026-10-06`).

When the APS signature lands, aeoess adds its public key to `jwks.json`, the APS slot
version moves to the `-signed` form, and `verify.py` extends to verify all three.

Windows note: run the Python tools with `PYTHONUTF8=1` (fixtures contain `—`).
