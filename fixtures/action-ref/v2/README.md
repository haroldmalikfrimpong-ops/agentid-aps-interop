# fixtures/action-ref/v2 — framed `action_ref` (v2) next to the frozen raw-concat form (v1)

`action_ref` binds a receipt or attestation to one action tuple
`{agent_id, action_type, scope, timestamp_ms}`. Two constructions over the **same four fields**:

| Version | Construction | Property |
|---|---|---|
| `action_ref_version: 1` | `sha256hex( utf8(agent_id) ‖ utf8(action_type) ‖ utf8(scope) ‖ int64_be(timestamp_ms) )` — argentum-core *action-ref-v1*, raw concatenation | **Tuple-ambiguous.** No field framing: bytes can move across a field boundary without changing the preimage. `("read","conformance-fixture")` and `("rea","dconformance-fixture")` hash identically. |
| `action_ref_version: 2` | `sha256hex( JCS({agent_id, action_type, scope, timestamp_ms}) )` — RFC 8785 JSON Canonicalization Scheme, `timestamp_ms` as a JSON integer | **Framed / injective over the tuple.** Keys and string delimiters bind every field; the same collision pairs produce distinct digests. |

v1 is **frozen**: it is the value pinned in tag `interop-freeze-2026-10-01` and in
[babyblueviper1/preaction-governance-conformance#9](https://github.com/babyblueviper1/preaction-governance-conformance/pull/9)
(`adapters/agentid.fixtures/positive.raw.json`, `binding.action_ref`). Nothing here changes it;
`positive-pinned-pr9-tuple.json` reproduces that exact value from the tuple. v1 should not be
treated as an exact authorization binding — that is the finding these vectors document
([#177, astrogilda](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5944104681)).

v2 is the framed form proposed in reply. JCS was chosen over length-prefixing because it is the
construction the cross-builder "one envelope → one id" vector on crewAI#4877 converged on, so one
form serves both threads. Emitters that adopt it set `action_ref_version: 2` beside the value so a
verifier knows which recomputation applies.

## Vectors

| File | What it shows | `expected` |
|---|---|---|
| `positive-pinned-pr9-tuple.json` | the PR #9 tuple (`agent_d1b7ef01f9af191f`, `read`, `conformance-fixture`, `1790882271509` = ms of `2026-10-01T19:17:51.509Z`) under v1 and v2 | `v1 == 6fe8b805…5ecb` (the pinned fixture value) |
| `negative-collision-action-type-scope-boundary.json` | `read`+`conformance-fixture` vs `rea`+`dconformance-fixture` | v1 preimage identical, v1 collides, v2 does not |
| `negative-collision-agent-id-action-type-boundary.json` | `agent_d1b7ef01f9af191f`+`read` vs `agent_d1b7ef01f9af191fr`+`ead` | v1 preimage identical, v1 collides, v2 does not |
| `control-distinct-tuples.json` | two genuinely different scopes | neither construction collides |

Collision pair values (same `agent_id`, same `timestamp_ms`):

```
a = ("read",  "conformance-fixture")   v1 6fe8b805ca46d0f71f06b1b4b3301be537ffd53cedb8726df2545c3369445ecb
b = ("rea",  "dconformance-fixture")   v1 6fe8b805ca46d0f71f06b1b4b3301be537ffd53cedb8726df2545c3369445ecb   ← identical
a                                      v2 08dae3cc5023ccad5b8b978e0b6dda181cc92cc10f28359015fc47d5bcc48ac2
b                                      v2 71411f6671a959bf2e7450355cca6aec63014c5c0e3fad2fb1ce7d76c72b9287   ← distinct
```

## Verify

```
python3 tools/action_ref_v2.py          # recompute every vector, assert `expected`; exit 0 iff all hold
python3 tools/action_ref_v2.py --emit   # also print the recomputed values
```

Stdlib only. For these payloads (flat object, ASCII strings, one integer < 2^53) RFC 8785 canonical
form equals `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`; when the
`jcs` package is installed the tool additionally asserts byte-equality with `jcs.canonicalize`.

Note: the `action_ref` fields inside `fixtures/aps/**` are APS receipt identifiers (`act_…`) in
aeoess's vocabulary, not this construction; they are intentionally not labelled here.
