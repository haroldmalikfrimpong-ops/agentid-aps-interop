# Optional fourth signal: receipt-graph risk policy

This is an offline reference policy for the adversarial fixtures accepted in
[issue #12](https://github.com/haroldmalikfrimpong-ops/agentid-aps-interop/issues/12).
It adds `slots.receipt_graph` under an explicitly selected composition profile,
`composed-v1-receipt-graph-v1`. It does not modify the existing composed-v1 or
composed-v2 verifiers, or turn reputation into an authorization gate.

An agent can have a valid identity, valid delegation, and clean code while its
interaction history provides inadequate support for a particular consumer's
exposure. Those are separate decisions. An authorization-only consumer may
ignore this entire policy; consumers choosing it must apply the returned cap.

## Consumer policy, not a fact inferred from signatures

`policy.json` is selected by the consumer independently of submitted receipts.
It admits two **synthetic** roots, with available budgets of five and one
synthetic exposure units. These values are test inputs, not dollars, observed
collateral, calibrated creditworthiness, or findings about either project.
Receipts bind to this policy's JCS/SHA-256 digest. A candidate cannot insert a
root or increase its budget through an extra receipt field.

The fixture assumes the consumer has admitted the roots and established their
available budgets. It does not discover independent principals or validate
the root's capital. The receipts are structural and unsigned. A production
adapter would first verify issuer/participant signatures, subject and action
binding, freshness, revocation, event uniqueness, and whatever independent-root
evidence its policy requires. Valid signatures alone establish none of those
economic independence assumptions.

## Exact rule

1. Preserve the existing native-slot decision. A native denial always wins,
   with final cap zero, even when graph support is present.
2. Deduplicate by `interaction_id`. Exact copies and wrappers with new
   `receipt_id` values contribute once. Conflicting payloads under the same
   receipt or interaction ID fail validation. Self interactions are rejected.
3. Make a directed edge from requester to worker for each distinct completed
   interaction, capacity one unit. Parallel distinct interactions add capacity.
4. Add a virtual source with one edge to each consumer-admitted root, capacity
   equal to that root's available budget. Compute maximum flow `F` from that
   source to the subject.
5. For requested amount `q > 0`, return `deny`/0 when `F = 0`, `cap`/`F` when
   `0 < F < q`, and `permit`/`q` when `F >= q`.

Every source-to-subject flow is bounded by the sum of the roots' available
budgets. A closed component with no root inflow has zero flow regardless of its
internal edge count. In `honest-edge-cap`, each ring member has one interaction
with the outside root, but that root has only one unit available across all its
outgoing paths: the ring cannot turn that one unit into five. Exact replay also
cannot create additional edge capacity.

This does **not** identify all Sybils. Unconnected honest newcomers also receive
zero under this strict policy. Multiple invented interactions with new IDs are
not detected as duplicates, and may saturate whatever externally supplied root
budget exists. The bound is the claim under test, not a claim of inclusion,
fairness, income, repayment, or fraud detection accuracy.

Budgets describe **one admission snapshot**. Reusing this evaluation for several
simultaneous requests without reserving/debiting root capacity would reuse the
same support. This fixture does not implement multi-request conservation,
revocation or loan accounting; a consumer needs those mechanisms separately.

## Envelope and diagnostics

```bash
pip install jcs jsonschema
python3 composed/adversarial/v1/verify.py --json
```

The JSON output contains four sibling slots (`agentid`, `aps`, `agentgraph`,
`receipt_graph`), `native_composite`, and `consumer_composite`. The graph slot
binds its policy and input evidence by digest, reports the flow and cap, and
keeps the count of unique and ignored duplicate interactions. Its category is
`consumer_risk_policy`, not a provenance/identity gate. The native v1 verifier
is reused for native slot versions, subject binding, APS chain hashing and gate
semantics. No fixture's expected block enters the calculation.

`native_composite.gate_states` separates AgentID certificate validity from key
lifecycle, and reports the APS delegation and AgentGraph security predicates.
Key lifecycle preserves `deprecated`, `revoked`, and `compromised` diagnostics;
an active key with a revocation timestamp is reported as `revoked`. Wallet,
standalone revocation, and policy gates are `not_applicable` in this profile;
native revocations are already handled in the identity/key and delegation slots.
For multiple failing gates, `decisive_gate` takes the first in identity, key
lifecycle, delegation, security order; `failing_gates` retains every failure.
These diagnostics use the historical native v1 structural predicates, not live
DID resolution, signature validation, or a new time-window policy.

Exit zero means every machine-readable expected outcome matches: each supplied
native gate state, the exact set of failing gates, decisive gate, native decision,
graph result, and consumer result. The four evaluated native gate expectations
and the decisive/graph/consumer expectations are required by this profile;
unrecognized assertions are rejected. The `reasoning` string is explanatory
prose, not an executable assertion. Exit one means a fixture or expectation
failed. A validation error is not a completed trust decision.

## Verification

```bash
python3 composed/adversarial/v1/verify.py
python3 -m unittest discover -s composed/adversarial/v1 -p 'test_*.py' -v
python3 composed/adversarial/v1/generate.py --check

# Existing suites, unchanged:
python3 composed/v1/verify.py
python3 composed/v2/verify.py
python3 composed/v2/generate.py --check
python3 tools/action_ref_v2.py
```

Tests cover the five hand-specified outcomes, individual native-oracle tampering,
missing or unrecognized assertions, valid native-denial diagnostics, replay aliases,
conflicting receipts, candidate root injection, policy/subject/chain binding,
missing native state, native-denial precedence, and larger closed components.
The flow implementation is also compared with an independently enumerated
minimum cut on 40 deterministic small graphs, including antiparallel edges.
A socket-connect guard checks that the five evaluations stay offline.

Authored by Codex (AI) for the microcredit team; see
[fixture attribution](../../../fixtures/adversarial/v1/README.md).
