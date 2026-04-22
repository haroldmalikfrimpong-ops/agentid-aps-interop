# composed/v1/ — three-signal worked examples

Composed-envelope fixtures that carry the AgentID, APS, and AgentGraph signals together for
a single subject DID. These are the first end-to-end interop artifacts that stitch the three
issuer slots into one object a consumer can verify.

Source threads: #5 (slot shapes) and #6 (AgentGraph schema amendment + fixtures).

## What a composed-v1 envelope is

Three issuers each produce a single-signal attestation about the same subject:

- **AgentID** — identity posture (DID resolution, certificate state, key lifecycle,
  wallet binding).
- **APS** — authorization posture (delegation chain with scope + temporal window, cascade
  revocation, monotonic narrowing).
- **AgentGraph** — security posture (static analysis, secret scan, dependency audit over
  the subject's linked artifact).

A composed-v1 envelope carries all three attestations as sibling slots under one root, with
a shared `subject_did` binding them to the same agent. The composed artifact is the
consumer-facing deliverable: one object, three independent signals, one composite verdict.

```json
{
  "composition_version": "composed-v1",
  "subject_did": "did:web:getagentid.dev:agent:agent_interop_test_001",
  "issued_at": "2026-04-21T21:00:00Z",
  "slots": {
    "agentid": { /* agentid_attestation payload verbatim */ },
    "aps":     { /* aps_delegation payload verbatim    */ },
    "agentgraph": { /* agentgraph_scan payload verbatim */ }
  },
  "expected_composite": {
    "decision": "permit" | "deny",
    "decisive_signal": "agentid" | "aps" | "agentgraph" | "all_passed",
    "failing_slots": ["agentid" | "aps" | "agentgraph"],
    "reasoning": "..."
  }
}
```

## The subject-DID binding rule

**Every slot's subject DID must equal the envelope-level `subject_did` verbatim.** A
composed artifact where the slots disagree about the subject is not a composed attestation
about one agent — it's three attestations about different agents glued together, which is a
different (and unspecified) object.

- AgentGraph slot carries `subject_did` directly.
- APS slot carries `subject_did` directly.
- AgentID's v1 slot (as currently shipped in `fixtures/agentid/v1/`) uses `did` rather
  than `subject_did`. This is a naming discrepancy between the AgentID slot shape declared
  on #5 (`agentid-identity-v1-structural` with `subject_did`) and the actual v1 fixtures
  (semver version + `did` field). `verify.py` accepts either key for AgentID. Harold's
  team is expected to reconcile this in a follow-up so composed envelopes speak a single
  vocabulary.

## Two-level version discipline

The envelope carries `composition_version` (currently `"composed-v1"`). Each slot
independently carries its own native version string per that issuer's cadence:

| Slot | Native version string |
|------|----------------------|
| agentid | `"agentid-identity-v1-structural"` (declared) or a semver like `"1.1.0"` (shipped) |
| aps | `"aps-v2-structural"` (slot-shape label — the `-v2-` tracks the APS crate version that first published this slot shape, not the envelope schema generation) |
| agentgraph | `"agentgraph-scan-v1-structural"` |

Issuers cadence their native slot versions independently. The envelope bumps
`composition_version` only when the outer-envelope contract changes (e.g., signed-form
requirements in v2).

## How a consumer iterates a composed-v1 envelope

```python
def verify_composed(envelope, verifiers):
    # 1. subject-DID binding
    subject = envelope["subject_did"]
    for slot_name, slot in envelope["slots"].items():
        slot_subject = slot.get("subject_did") or slot.get("did")
        assert slot_subject == subject, f"{slot_name} subject mismatch"

    # 2. each slot validated against its native verifier
    per_slot = {}
    for slot_name, slot in envelope["slots"].items():
        per_slot[slot_name] = verifiers[slot_name].verify(slot)

    # 3. AND-compose
    if all(v["passing"] for v in per_slot.values()):
        return {"decision": "permit", "per_slot": per_slot}
    failing = [n for n, v in per_slot.items() if not v["passing"]]
    return {"decision": "deny", "failing_slots": failing, "per_slot": per_slot}
```

`verifiers` is a per-slot-role map — each verifier is supplied by the consumer and knows
how to verify its own issuer's native shape. `verify.py` in this directory is a
lightweight, issuer-neutral stand-in for development; production consumers will compose
their own verifiers (for example: APS SDK for the APS slot, AgentGraph Python client for
the security slot).

## Running `verify.py`

```
pip install jcs
python3 composed/v1/verify.py
```

Expected output on a clean tree: three fixtures, 51 checks, all pass. Exit 0. A failure
prints which check failed under which fixture and exits 1.

What it checks per fixture:

1. `composition_version == "composed-v1"`.
2. All three slots (`agentid`, `aps`, `agentgraph`) present.
3. Each slot's subject DID matches the envelope-level `subject_did`.
4. Each slot's `version` field is in the expected set for that slot role.
5. APS `delegation_chain_root` recomputes correctly from `delegation_chain` via JCS +
   SHA-256.
6. Each slot payload JCS-canonicalizes without error.
7. `expected_composite.decision` matches the naive all-must-pass rule applied to each
   slot's passing state (derived per slot: AgentID key_status active + certificate valid +
   not revoked; APS no ancestor revocation + monotonic narrowing; AgentGraph no F grades +
   zero critical deps).
8. `expected_composite.failing_slots` matches the set computed by rule 7.

## The three fixtures

| Fixture | Slots source | Expected |
|---------|-------------|----------|
| `agent_interop_test_001/happy-path.json` | AgentID happy, APS happy, AgentGraph happy | permit, decisive_signal `all_passed` |
| `agent_interop_test_001/aps-revoked-delegation.json` | AgentID happy, APS revoked-delegation, AgentGraph happy | deny, decisive_signal `aps`, failing_slots `[aps]` |
| `agent_interop_test_001/agentgraph-secret-leaked.json` | AgentID happy, APS happy, AgentGraph secret-leaked | deny, decisive_signal `agentgraph`, failing_slots `[agentgraph]` |

The two deny fixtures prove that a single-slot failure propagates to a composite denial
under the all-must-pass rule, and that the `decisive_signal` field names exactly which
signal tipped the verdict (no collapse to a single confidence score — every consumer can
trace which issuer's dimension failed).

Slot payloads are verbatim copies of the relevant `inputs.<slot>` block from the
single-signal fixtures under `fixtures/<issuer>/v1/`. A consumer that already validates
Harold's or Kenne's or our v1 fixtures bit-for-bit will validate composed slots
bit-for-bit.

## What v2 adds

v2 is the lockstep signed form. Per the agreement on #5, each slot carries:

- `signature` — raw signature bytes.
- `signer_key_id` — JWKS reference for the issuer's signing key.
- A canonical signed-bytes contract (JCS-canonicalization of the slot's payload minus the
  signature fields, hashed and signed).

The composed envelope may additionally carry its own envelope-level signature over the
composition metadata (composition_version, subject_did, issued_at, per-slot fingerprints).
That's still open design — v1 here establishes the shape before v2 adds the crypto layer.

v2 slot versions will be:

- `agentid-identity-v1-signed`
- `aps-v2-signed`
- `agentgraph-scan-v1-signed`

## Contributors

- **Harold (haroldmalikfrimpong-ops)** — AgentID slot shape, v1 fixtures, schema baseline.
- **Kenne (kenneives)** — AgentGraph slot shape, v1 fixtures, schema amendment 1.0.1 →
  1.1.0 (PR #6).
- **aeoess** — APS slot shape, APS v1 fixtures, composed-v1 envelope contract + fixtures,
  `verify.py`, this README, schema amendment 1.1.0 → 1.2.0 (APS v1-structural shape).

## JEP slot

`slots.jep` carries a JEP receipt as a `decision_event` signal.

Unlike AgentID, APS, and AgentGraph, JEP is not part of the naive all-must-pass composite. A JEP receipt is a signed judgment / decision-event record, not a policy-engine output and not a fourth pass/fail gate.

For composed-v1, the validator checks:

- shared `subject_did` binding;
- `version: "jep-v1"`;
- `category: "decision_event"`;
- JCS canonicalizability;
- `aud` binding between `slots.jep.aud` and the inner JEP `payload.aud`;
- `payload_hash` recomputation where present;
- `payload.ref` linkage to `references[]` with `kind: "prior_event"`;
- referenced artifact hash integrity when `artifact_path` is present.

The JEP slot is then skipped from the composite decision so the existing AgentID + APS + AgentGraph gate semantics remain unchanged.
