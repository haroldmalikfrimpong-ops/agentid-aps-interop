#!/usr/bin/env python3
"""
composed/v1/verify.py — cross-issuer validator for composed-v1 envelopes.

This validator is issuer-neutral. It checks the existing AgentID + APS +
AgentGraph all-must-pass composite, and also recognizes an optional JEP slot.


Per-envelope checks:
  1. subject_did at envelope root matches the DID carried in each slot.
     - AgentGraph and APS carry `subject_did` directly.
     - AgentID's v1-shipped slot uses `did` (discrepancy with the slot shape declared on
       haroldmalikfrimpong-ops/agentid-aps-interop#5 but matches what Harold's
       fixtures/agentid/v1/ actually ships). We accept either.
  2. Each slot's `version` field matches an expected set for that slot role.
     - AgentGraph: 'agentgraph-scan-v1-structural'
     - APS: 'aps-v2-structural'
     - AgentID: either 'agentid-identity-v1-structural' (declared) or a semver (e.g. '1.1.0')
       (shipped). Both are accepted to track the current AgentID fixture state in Harold's repo.
  3. APS delegation_chain_root is recomputed from delegation_chain via JCS + SHA-256 and
     matches the declared value.
  4. Each slot payload is independently JCS-canonicalizable without error.
  5. expected_composite.decision matches the naive composition rule:
     permit iff all evaluated slots have a passing native state, else deny.
     Native passing state per slot is derived from fixture-level ground truth — see
     _slot_passes() for the exact rule applied per slot role.

Runtime:
  Python 3.10+ recommended (this script uses only 3.9-compatible syntax so it also runs on
  older interpreters that CI might provision).
JEP rule for composed-v1:
- `slots.jep` is checked as `category: decision_event` evidence.
- It is NOT included in the naive all-must-pass composite.
- The verifier still checks subject binding, JCS canonicalizability, aud binding,
  payload hash, and prior-event reference integrity where `payload.ref` is set.

Dependencies:
    pip install jcs

Exit code:
    0 all fixtures pass all checks
    1 any fixture fails any check
    2 setup/dependency error
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import jcs  # RFC 8785 canonicalization
except ImportError:
    sys.stderr.write("ERROR: jcs not installed. Run: pip install jcs\n")
    sys.exit(2)

GATING_SLOTS = ("agentid", "aps", "agentgraph", "hive")
CHECKED_SLOTS = ("agentid", "aps", "agentgraph", "jep", "hive")

SLOT_EXPECTED_VERSIONS = {
    "agentgraph": {"agentgraph-scan-v1-structural"},
    "aps": {"aps-v2-structural"},
    # AgentID: declared slot version on #5 is agentid-identity-v1-structural.
    # Shipped v1 fixtures use semver because they predate the slot-version convention.
    "agentid": {"agentid-identity-v1-structural", "1.0.0", "1.0.1", "1.1.0", "1.2.0"},

    "hive": {"hive-tier-v1"},
    "jep": {"jep-v1"},
}


def _canonicalize(obj: Any) -> bytes:
    return jcs.canonicalize(obj)


def _sha256_jcs(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonicalize(obj)).hexdigest()


def _slot_subject_did(slot: Dict[str, Any], slot_name: str) -> str:
    """Return the DID this slot claims as its subject.

    AgentID currently uses `did`; other slots use `subject_did`.
    """
    if "subject_did" in slot:
        return slot["subject_did"]
    if slot_name == "agentid" and "did" in slot:
        return slot["did"]
    raise ValueError(f"slot '{slot_name}' has no subject_did or did field")


def _slot_passes(slot: Dict[str, Any], slot_name: str) -> bool:
    """Return whether a gating slot passes in its native frame.

    JEP is intentionally not handled here; it is a decision_event record, not a
    pass/fail gate for the naive composite.
    """
    if slot_name == "agentid":
        key_status = slot.get("key_status", "active")
        cert_valid = slot.get("certificate_valid", True)
        revoked_at = slot.get("revoked_at")
        return key_status == "active" and cert_valid is True and revoked_at is None

    if slot_name == "aps":
        chain = slot.get("delegation_chain", [])
        if not chain:
            return False
        if any(h.get("revoked_at") for h in chain):
            return False
        for i in range(1, len(chain)):
            parent_scope = set(chain[i - 1].get("scope", []))
            child_scope = set(chain[i].get("scope", []))
            if not child_scope.issubset(parent_scope):
                return False
        return True

    if slot_name == "agentgraph":
        gates = slot.get("gates", {})
        for gate_name in ("static_analysis", "secret_scan", "dependency_audit"):
            g = gates.get(gate_name)
            if not g:
                return False
            if g.get("grade") == "F":
                return False
        if gates.get("dependency_audit", {}).get("critical", 0) > 0:
            return False
        return True


    if slot_name == "hive":
        # Hive tier gate: tier must be a known tier (not VOID), key active,
        # non_transferable must be True, and hit_rate >= 0.8
        tier = slot.get("agent_tier", "VOID")
        non_transferable = slot.get("non_transferable", False)
        hit_rate = slot.get("hit_rate", 0.0)
        known_tiers = {"MOZ", "HAWX", "EMBR", "SOLX", "FENR"}
        return tier in known_tiers and non_transferable is True and hit_rate >= 0.8

        raise ValueError(f"unknown slot name: {slot_name}")
raise ValueError(f"unknown gating slot name: {slot_name}")


def _recompute_delegation_chain_root(chain: List[Dict[str, Any]]) -> str:
    return _sha256_jcs(chain)


def _jep_required_fields_present(payload: Dict[str, Any]) -> bool:
    required = {"jep", "verb", "who", "when", "what", "nonce", "aud", "ref", "sig"}
    return required.issubset(payload.keys())


def _reference_matches_payload_ref(ref_item: Dict[str, Any], payload_ref: str) -> bool:
    return (
        ref_item.get("kind") == "prior_event"
        and (
            ref_item.get("hash") == payload_ref
            or ref_item.get("urn") == f"urn:jep:{payload_ref}"
        )
    )


def _check_jep_reference_artifact(
    ref_item: Dict[str, Any], payload_ref: str, repo_root: Path
) -> Tuple[str, bool]:
    artifact_path = ref_item.get("artifact_path")
    if not artifact_path:
        return "slots.jep prior_event reference artifact_path absent (hash-only reference)", True

    full_path = repo_root / artifact_path
    if not full_path.exists():
        return f"slots.jep prior_event artifact exists: {artifact_path}", False

    try:
        prior_event = json.load(open(full_path, encoding="utf-8"))
        prior_hash = _sha256_jcs(prior_event)
    except Exception:
        return f"slots.jep prior_event artifact rehashes: {artifact_path}", False

    return (
        f"slots.jep prior_event artifact hash matches payload.ref ({artifact_path})",
        prior_hash == payload_ref,
    )


def _check_jep_slot(slot: Dict[str, Any], env_subject: Optional[str], repo_root: Path) -> List[Tuple[str, bool]]:
    rows: List[Tuple[str, bool]] = []

    rows.append(("slots.jep.category == 'decision_event'", slot.get("category") == "decision_event"))
    rows.append(("slots.jep.validity_temporal == 'sequence'", slot.get("validity_temporal") == "sequence"))
    rows.append(("slots.jep skipped from naive all-must-pass composite", True))

    payload = slot.get("payload")
    if not isinstance(payload, dict):
        rows.append(("slots.jep.payload is object", False))
        return rows
    rows.append(("slots.jep.payload is object", True))

    rows.append(("slots.jep.payload has JEP core fields", _jep_required_fields_present(payload)))
    rows.append(("slots.jep.payload.jep == '1'", payload.get("jep") == "1"))
    rows.append(("slots.jep.payload.verb in J/D/T/V", payload.get("verb") in {"J", "D", "T", "V"}))
    rows.append(("slots.jep.payload.aud mirrors slots.jep.aud", payload.get("aud") == slot.get("aud")))
    rows.append(("slots.jep.payload.who == slots.jep.subject_did", payload.get("who") == slot.get("subject_did")))
    rows.append(("slots.jep.subject_did == envelope subject_did", slot.get("subject_did") == env_subject))

    declared_payload_hash = slot.get("payload_hash")
    if declared_payload_hash:
        rows.append(("slots.jep.payload_hash matches JCS+SHA256 recompute", declared_payload_hash == _sha256_jcs(payload)))

    payload_ref = payload.get("ref")
    if payload_ref is None:
        rows.append(("slots.jep.payload.ref is root/null or matched", True))
        return rows

    references = slot.get("references", [])
    matching_refs = [r for r in references if isinstance(r, dict) and _reference_matches_payload_ref(r, payload_ref)]
    rows.append(("slots.jep.payload.ref appears in references[] as kind prior_event", bool(matching_refs)))

    for ref_item in matching_refs:
        rows.append(_check_jep_reference_artifact(ref_item, payload_ref, repo_root))

    return rows


def verify_envelope(path: Path) -> Tuple[str, List[Tuple[str, bool]]]:
    rows: List[Tuple[str, bool]] = []
    envelope = json.load(open(path, encoding="utf-8"))
    name = path.name
    repo_root = Path(__file__).resolve().parents[2]

    rows.append(("composition_version=='composed-v1'", envelope.get("composition_version") == "composed-v1"))

    env_subject = envelope.get("subject_did")
    rows.append(("subject_did present", env_subject is not None))

    slots = envelope.get("slots", {})


        # Check 2: core slots always required; hive slot only required in hive-specific fixtures
    for slot_name in ("agentid", "aps", "agentgraph"):
# Existing composed-v1 contract: the three gating slots are required.
    for slot_name in GATING_SLOTS:
        rows.append((f"slots.{slot_name} present", slot_name in slots))
    if "hive" in path.name:
        rows.append(("slots.hive present", "hive" in slots))


    # Check 3: subject_did consistency
    for slot_name in ("agentid", "aps", "agentgraph", "hive"):
# Optional JEP decision_event slot is checked when present.
    for slot_name in CHECKED_SLOTS:
        if slot_name not in slots:
            continue
        try:
            slot_did = _slot_subject_did(slots[slot_name], slot_name)
            rows.append((f"slots.{slot_name} subject_did == envelope subject_did", slot_did == env_subject))
        except ValueError:
            rows.append((f"slots.{slot_name} subject_did extraction", False))

    for slot_name, expected_set in SLOT_EXPECTED_VERSIONS.items():
        if slot_name not in slots:
            continue
        version = slots[slot_name].get("version")
        rows.append((f"slots.{slot_name}.version in expected set", version in expected_set))

    aps_slot = slots.get("aps")
    if aps_slot:
        declared = aps_slot.get("delegation_chain_root")
        chain = aps_slot.get("delegation_chain", [])
        recomputed = _recompute_delegation_chain_root(chain)
        rows.append(("aps delegation_chain_root matches JCS+SHA256 recompute", declared == recomputed))


    # Check 6: JCS-canonicalize each slot
    for slot_name in ("agentid", "aps", "agentgraph", "hive"):
for slot_name in CHECKED_SLOTS:
        if slot_name not in slots:
            continue
        try:
            _canonicalize(slots[slot_name])
            rows.append((f"slots.{slot_name} JCS-canonicalizes", True))
        except Exception:
            rows.append((f"slots.{slot_name} JCS-canonicalizes", False))


    # Check 7: naive composite rule agreement
    passes = {s: _slot_passes(slots[s], s) for s in ("agentid", "aps", "agentgraph", "hive") if s in slots}
if "jep" in slots:
        rows.extend(_check_jep_slot(slots["jep"], env_subject, repo_root))

    # Naive composite still gates only AgentID + APS + AgentGraph.
    passes = {s: _slot_passes(slots[s], s) for s in GATING_SLOTS if s in slots}
    all_pass = all(passes.values())
    expected_decision = envelope.get("expected_composite", {}).get("decision")
    computed_decision = "permit" if all_pass else "deny"
    rows.append((
        f"expected decision '{expected_decision}' matches naive rule '{computed_decision}'",
        expected_decision == computed_decision,
    ))

    declared_failing = set(envelope.get("expected_composite", {}).get("failing_slots", []))
    computed_failing = {s for s, ok in passes.items() if not ok}
    rows.append((
        f"failing_slots match (declared {sorted(declared_failing)} vs computed {sorted(computed_failing)})",
        declared_failing == computed_failing,
    ))

    return name, rows


def main() -> int:
    here = Path(__file__).parent
    fixtures_dir = here / "agent_interop_test_001"
    if not fixtures_dir.exists():
        sys.stderr.write(f"ERROR: {fixtures_dir} does not exist\n")
        return 2

    fixture_paths = sorted(fixtures_dir.glob("*.json"))
    if not fixture_paths:
        sys.stderr.write(f"ERROR: no composed fixtures found under {fixtures_dir}\n")
        return 2

    total_checks = 0
    total_passed = 0
    failing_fixtures: List[str] = []

    for path in fixture_paths:
        name, rows = verify_envelope(path)
        print(f"\n== {name} ==")
        fixture_all_pass = True
        for label, ok in rows:
            total_checks += 1
            if ok:
                total_passed += 1
                print(f" PASS {label}")
            else:
                fixture_all_pass = False
                print(f" FAIL {label}")
        if not fixture_all_pass:
            failing_fixtures.append(name)

    print("\n== summary ==")
    print(f" fixtures examined: {len(fixture_paths)}")
    print(f" checks passed: {total_passed}/{total_checks}")
    print(f" fixtures clean: {len(fixture_paths) - len(failing_fixtures)}/{len(fixture_paths)}")

    if failing_fixtures:
        print(f" FAILURES in: {', '.join(failing_fixtures)}")
        return 1

    print(" status: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
