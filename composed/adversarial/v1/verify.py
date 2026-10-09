#!/usr/bin/env python3
"""Offline reference for an optional receipt-graph signal after native gates.

AI-authored by Codex for the microcredit team, following issue #12.
This is a structural, consumer-selected policy, not an issuer's live scorer.
The expected_result block is an oracle used only by verify_fixture(), never by
evaluate(). Root budgets come from the separately selected consumer policy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import sys
from collections import deque
from pathlib import Path

import jcs
from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIXTURES = ROOT / "fixtures" / "adversarial" / "v1"
NATIVE_INPUTS = {
    "agentid": "agentid_attestation",
    "aps": "aps_delegation",
    "agentgraph": "agentgraph_scan",
}
PROFILE = "composed-v1-receipt-graph-v1"


def digest(value):
    return "sha256:" + hashlib.sha256(jcs.canonicalize(value)).hexdigest()


def load_policy():
    """The caller/consumer chooses policy; a submitted receipt cannot add roots."""
    policy = json.loads((HERE / "policy.json").read_text(encoding="utf-8"))
    if policy["policy_id"] != "rooted-receipt-cap-v1":
        raise ValueError("unsupported consumer policy")
    if policy["unit_capacity_per_distinct_interaction"] != 1:
        raise ValueError("this profile requires one unit per distinct interaction")
    roots = policy["roots"]
    ids = [root["did"] for root in roots]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate consumer root")
    for root in roots:
        if not isinstance(root["did"], str) or not root["did"].startswith("did:"):
            raise ValueError("invalid consumer root DID")
        if type(root["available_units"]) is not int or root["available_units"] < 0:
            raise ValueError("root budget must be a nonnegative integer")
    return policy


def max_flow_to_subject(receipts, roots, subject):
    """Integral max flow; cycles only redistribute source-bounded capacity."""
    source = object()  # A candidate DID cannot collide with this synthetic node.
    residual = {}

    def edge(left, right, capacity):
        residual.setdefault(left, {})
        residual.setdefault(right, {})
        residual[left][right] = residual[left].get(right, 0) + capacity
        residual[right].setdefault(left, 0)

    for root in roots:
        edge(source, root["did"], root["available_units"])
    for receipt in receipts:
        edge(receipt["requester_did"], receipt["worker_did"], 1)

    total = 0
    while True:
        parents = {source: None}
        queue = deque([source])
        while queue and subject not in parents:
            left = queue.popleft()
            for right, capacity in residual.get(left, {}).items():
                if capacity > 0 and right not in parents:
                    parents[right] = left
                    queue.append(right)
        if subject not in parents:
            return total
        amount = None
        node = subject
        while node is not source:
            previous = parents[node]
            capacity = residual[previous][node]
            amount = capacity if amount is None else min(amount, capacity)
            node = previous
        node = subject
        while node is not source:
            previous = parents[node]
            residual[previous][node] -= amount
            residual[node][previous] += amount
            node = previous
        total += amount


def evaluate_graph(graph, policy):
    if graph["policy_id"] != policy["policy_id"] or graph["policy_hash"] != digest(policy):
        raise ValueError("receipt graph does not bind to the consumer-selected policy")
    by_id, by_interaction = {}, {}
    duplicates = 0
    for receipt in graph["receipts"]:
        if receipt["requester_did"] == receipt["worker_did"]:
            raise ValueError("self interaction is outside this receipt profile")
        payload = {k: v for k, v in receipt.items() if k != "receipt_id"}
        receipt_id, interaction_id = receipt["receipt_id"], receipt["interaction_id"]
        for index, key in ((by_id, receipt_id), (by_interaction, interaction_id)):
            if key in index and index[key] != payload:
                raise ValueError("conflicting payload for receipt or interaction ID")
        if interaction_id in by_interaction:
            duplicates += 1
        by_id[receipt_id] = payload
        by_interaction[interaction_id] = payload

    flow = max_flow_to_subject(list(by_interaction.values()), policy["roots"], graph["subject_did"])
    requested = graph["requested_units"]
    decision = "deny" if flow == 0 else "cap" if flow < requested else "permit"
    reason = {
        "deny": "no_rooted_support",
        "cap": "request_exceeds_rooted_cap",
        "permit": "request_within_rooted_cap",
    }[decision]
    reasons = [reason]
    if duplicates:
        reasons.append("duplicate_interactions_ignored")
    return {
        "decision": decision,
        "cap_units": min(flow, requested),
        "max_flow_units": flow,
        "unique_interactions": len(by_interaction),
        "duplicate_interactions": duplicates,
        "reason_codes": reasons,
    }


def _native_verifier():
    path = ROOT / "composed" / "v1" / "verify.py"
    spec = importlib.util.spec_from_file_location("interop_composed_v1", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _native_diagnostics(slots, passes):
    """Expand the native v1 slot predicates into the root schema's gate names.

    AgentID identity and key lifecycle have distinct diagnostics, even though
    composed-v1 combines both in one slot. The other three root-schema gates
    are not independently evaluated by this structural profile.
    """
    identity = slots["agentid"]
    key_state = identity["key_status"]
    if key_state == "active":
        key_state = "passed" if identity["revoked_at"] is None else "revoked"
    # This order also defines the convenience decisive_gate when several fail.
    gates = {
        "identity_gate": "passed" if identity["certificate_valid"] is True else "failed",
        "key_lifecycle_gate": key_state,
        "delegation_gate": "passed" if passes["aps"] else "failed",
        "security_gate": "passed" if passes["agentgraph"] else "failed",
        "wallet_state_gate": "not_applicable",
        "revocation_gate": "not_applicable",
        "policy_gate": "not_applicable",
    }
    failing = [name for name, state in gates.items() if state not in {"passed", "not_applicable"}]
    return {
        "gate_states": gates,
        "failing_gates": failing,
        "decisive_gate": failing[0].removesuffix("_gate") if failing else "all_passed",
    }


def evaluate(vector, policy=None):
    """Compute from inputs only; does not read scenario labels or expected_result."""
    policy = load_policy() if policy is None else policy
    schema = json.loads((ROOT / "vector.schema.json").read_text(encoding="utf-8"))
    # Validate only the inputs in the computation path. Oracle validation is separate.
    input_schema = {
        "$defs": schema["$defs"],
        **schema["properties"]["inputs"],
        "required": [*NATIVE_INPUTS.values(), "receipt_graph"],
        "additionalProperties": False,
    }
    Draft202012Validator(input_schema, format_checker=FormatChecker()).validate(vector["inputs"])
    slots = {name: copy.deepcopy(vector["inputs"][field]) for name, field in NATIVE_INPUTS.items()}
    subject = vector["subject"]["did"]
    graph = vector["inputs"]["receipt_graph"]
    if graph["subject_did"] != subject:
        raise ValueError("receipt graph subject differs from vector subject")
    required_identity = {"key_status", "certificate_valid", "revoked_at"}
    if not required_identity.issubset(slots["agentid"]):
        raise ValueError("native identity state must be explicit")

    native = _native_verifier()
    errors = []
    for name, slot in slots.items():
        if native._slot_subject_did(slot, name) != subject:
            errors.append(f"{name} subject binding")
        if slot.get("version") not in native.SLOT_EXPECTED_VERSIONS[name]:
            errors.append(f"{name} version")
        jcs.canonicalize(slot)
    aps = slots["aps"]
    if aps.get("delegation_chain_root") != native._recompute_delegation_chain_root(aps.get("delegation_chain", [])):
        errors.append("APS delegation chain hash")
    if errors:
        raise ValueError("invalid native envelope: " + "; ".join(errors))
    passes = {name: native._slot_passes(slot, name) for name, slot in slots.items()}
    failing = sorted(name for name, passing in passes.items() if not passing)
    native_decision = "deny" if failing else "permit"
    graph_result = evaluate_graph(graph, policy)
    if failing:
        composite = {"decision": "deny", "cap_units": 0, "failing_slots": failing,
                     "decisive_signal": failing[0]}
    else:
        composite = {"decision": graph_result["decision"], "cap_units": graph_result["cap_units"],
                     "failing_slots": [], "decisive_signal": "receipt_graph"}
    slots["receipt_graph"] = {
        "version": "receipt-graph-v1-structural",
        "subject_did": subject,
        "category": "consumer_risk_policy",
        "policy_id": policy["policy_id"],
        "policy_hash": digest(policy),
        "evidence_hash": digest(graph["receipts"]),
        "units": policy["units"],
        **graph_result,
    }
    return {
        "composition_version": PROFILE,
        "subject_did": subject,
        "issued_at": policy["evaluation_time"],
        "slots": slots,
        "native_composite": {"decision": native_decision, "failing_slots": failing,
                             **_native_diagnostics(slots, passes)},
        "consumer_composite": composite,
        "limitations": ["structural receipts; signatures not verified",
                        "root admission and budgets are consumer assumptions",
                        "one snapshot; no cross-request reservation accounting"],
    }


def verify_fixture(path):
    vector = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "vector.schema.json").read_text(encoding="utf-8"))
    # This profile publishes all four evaluated native gates, plus the graph
    # and consumer oracles. Do not let deletion silently remove an assertion.
    expected_schema = schema["properties"]["expected_result"]
    expected_schema["required"] = [*expected_schema["required"], "identity_gate",
                                   "key_lifecycle_gate", "delegation_gate", "security_gate",
                                   "decisive_gate", "receipt_graph", "consumer_decision"]
    expected_schema["additionalProperties"] = False
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(vector)
    result = evaluate(vector)
    expected = vector["expected_result"]
    native = result["native_composite"]
    actual_graph = result["slots"]["receipt_graph"]
    graph_oracle = {name: actual_graph[name] for name in expected["receipt_graph"]}
    checks = [
        ("native decision", native["decision"] == expected["composite_decision"]),
        *[(name, state == expected[name]) for name, state in native["gate_states"].items()
          if name in expected],
        ("failing_gates", sorted(native["failing_gates"]) == sorted(expected["failing_gates"])),
        ("decisive_gate", native["decisive_gate"] == expected["decisive_gate"]),
        ("receipt graph", graph_oracle == expected["receipt_graph"]),
        ("consumer decision", result["consumer_composite"] == expected["consumer_decision"]),
    ]
    return vector["scenario"], checks, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="fixture JSON paths; default: all five cases")
    parser.add_argument("--json", action="store_true", help="print computed four-slot envelopes")
    args = parser.parse_args()
    paths = args.paths or sorted(FIXTURES.glob("*.json"))
    if not paths:
        parser.error("no fixture files")
    results, failures = [], []
    for path in paths:
        try:
            name, checks, result = verify_fixture(path)
            failed = [label for label, ok in checks if not ok]
            if failed:
                failures.append(f"{path.name}: {', '.join(failed)}")
            results.append({"scenario": name, "checks_passed": not failed, "envelope": result})
            if not args.json:
                final = result["consumer_composite"]
                print(f"{'FAIL' if failed else 'PASS'} {name}: {final['decision']}, cap={final['cap_units']}")
        except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
            failures.append(f"{path.name}: {error}")
        except Exception as error:
            # Includes jsonschema.ValidationError; fail closed with a useful diagnostic.
            failures.append(f"{path.name}: {type(error).__name__}: {error}")
    if args.json:
        print(json.dumps({"results": results, "failures": failures}, indent=2))
    else:
        print(f"{len(paths) - len(failures)}/{len(paths)} fixtures passed")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
