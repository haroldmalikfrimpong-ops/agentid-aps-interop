#!/usr/bin/env python3
"""
tools/action_ref_v2.py — recompute and check the action_ref v1/v2 vectors.

    python3 tools/action_ref_v2.py            # recompute every vector under fixtures/action-ref/v2, assert `expected`
    python3 tools/action_ref_v2.py --emit     # print the recomputed values (for regenerating the vectors)

Constructions (field set identical in both: agent_id, action_type, scope, timestamp_ms):

  v1  action_ref = SHA-256( utf8(agent_id) ‖ utf8(action_type) ‖ utf8(scope) ‖ int64_be(timestamp_ms) )
      argentum-core action-ref-v1, raw concatenation, no field framing. TUPLE-AMBIGUOUS:
      moving bytes across a field boundary ("read"+"conformance-fixture" vs
      "rea"+"dconformance-fixture") leaves the preimage — and the hash — unchanged.
      Labelled `action_ref_version: 1`. Frozen as pinned in interop-freeze-2026-10-01 and
      babyblueviper1/preaction-governance-conformance#9; it does not change.

  v2  action_ref = SHA-256( JCS({agent_id, action_type, scope, timestamp_ms}) )
      RFC 8785 JSON Canonicalization Scheme over the four-field object, timestamp_ms as a
      JSON integer. Framing is inherent (keys + string delimiters), so the tuple is bound
      injectively. Labelled `action_ref_version: 2`.

JCS note: for these payloads (flat object, ASCII string values, one non-negative integer
below 2^53) RFC 8785 canonical form is exactly
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. The script
uses that stdlib form and, when the `jcs` package is importable, asserts byte-equality with
`jcs.canonicalize` as a cross-check. Values with non-ASCII, floats, or nested structures
would need a full RFC 8785 implementation; none appear here.

Exit 0 iff every vector's recomputed v1/v2 and every `expected` assertion holds.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VEC_DIR = ROOT / "fixtures" / "action-ref" / "v2"

try:
    import jcs as _jcs  # optional cross-check
except ImportError:  # pragma: no cover
    _jcs = None


def canonical_json(obj) -> bytes:
    out = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if _jcs is not None:
        assert out == _jcs.canonicalize(obj), "stdlib canonical form != RFC 8785 JCS for this payload"
    return out


def action_ref_v1(agent_id: str, action_type: str, scope: str, timestamp_ms: int) -> str:
    pre = agent_id.encode() + action_type.encode() + scope.encode() + struct.pack(">q", timestamp_ms)
    return hashlib.sha256(pre).hexdigest()


def action_ref_v2(agent_id: str, action_type: str, scope: str, timestamp_ms: int) -> str:
    obj = {"agent_id": agent_id, "action_type": action_type, "scope": scope, "timestamp_ms": timestamp_ms}
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def _refs(t: dict) -> tuple[str, str]:
    args = (t["agent_id"], t["action_type"], t["scope"], int(t["timestamp_ms"]))
    return action_ref_v1(*args), action_ref_v2(*args)


def check_vector(path: Path, emit: bool) -> list[tuple[str, bool]]:
    v = json.loads(path.read_text(encoding="utf-8"))
    rows: list[tuple[str, bool]] = []
    tuples = v["tuples"]
    computed = {}
    for name, t in tuples.items():
        v1, v2 = _refs(t)
        computed[name] = (v1, v2)
        rows.append((f"{name}: action_ref_v1 recomputes", v1 == t["action_ref_v1"]))
        rows.append((f"{name}: action_ref_v2 recomputes", v2 == t["action_ref_v2"]))
        rows.append((f"{name}: versions labelled 1 and 2", t.get("action_ref_v1_version") == 1 and t.get("action_ref_v2_version") == 2))
        if emit:
            print(f"  {name}: v1={v1} v2={v2}")
    exp = v.get("expected", {})
    names = list(tuples)
    # pinned literal expectations: "<tuple>.action_ref_v1" / "<tuple>.action_ref_v2"
    for key, want in exp.items():
        if "." in key and key.rsplit(".", 1)[0] in computed:
            tname, which = key.rsplit(".", 1)
            got = computed[tname][0 if which == "action_ref_v1" else 1]
            rows.append((f"expected.{key} == {want[:16]}…", got == want))
    if len(names) == 2 and "v1_collides" in exp:
        (a1, a2), (b1, b2) = computed[names[0]], computed[names[1]]
        rows.append((f"expected.v1_collides == {exp['v1_collides']}", (a1 == b1) == exp["v1_collides"]))
        rows.append((f"expected.v2_collides == {exp['v2_collides']}", (a2 == b2) == exp["v2_collides"]))
        if "v1_preimage_identical" in exp:
            ta, tb = tuples[names[0]], tuples[names[1]]
            pa = ta["agent_id"].encode() + ta["action_type"].encode() + ta["scope"].encode() + struct.pack(">q", int(ta["timestamp_ms"]))
            pb = tb["agent_id"].encode() + tb["action_type"].encode() + tb["scope"].encode() + struct.pack(">q", int(tb["timestamp_ms"]))
            rows.append((f"expected.v1_preimage_identical == {exp['v1_preimage_identical']}", (pa == pb) == exp["v1_preimage_identical"]))
    return rows


def main() -> int:
    emit = "--emit" in sys.argv
    paths = sorted(VEC_DIR.glob("*.json"))
    if not paths:
        sys.stderr.write(f"no vectors under {VEC_DIR}\n")
        return 2
    total = passed = 0
    bad = []
    for p in paths:
        print(f"\n== {p.name} ==")
        rows = check_vector(p, emit)
        for label, ok in rows:
            total += 1
            passed += ok
            print(f"  {'PASS' if ok else 'FAIL'}  {label}")
            if not ok:
                bad.append(p.name)
    print(f"\n== summary ==\n  vectors: {len(paths)}\n  checks passed: {passed}/{total}")
    if bad:
        print("  FAILURES in:", ", ".join(sorted(set(bad))))
        return 1
    print("  status: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
