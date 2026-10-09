#!/usr/bin/env python3
"""Regenerate the five structural inputs; expected decisions are hand specified.

AI-authored by Codex for the microcredit team. No keys, signing or network.
This generator deliberately does not import the policy evaluator.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

import jcs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DESTINATION = ROOT / "fixtures" / "adversarial" / "v1"
SUBJECT = "did:web:getagentid.dev:agent:agent_interop_test_001"
SPONSOR = "did:example:graph-sponsor"
OUTSIDE = "did:example:outside-customer"


def receipt(number, requester, worker):
    return {
        "receipt_id": f"receipt-{number:03d}",
        "interaction_id": f"interaction-{number:03d}",
        "requester_did": requester,
        "worker_did": worker,
        "outcome": "completed",
        "completed_at": "2026-04-20T12:00:00Z",
        "fixture_form": "structural",
    }


def mesh(nodes):
    return [receipt(index, left, right)
            for index, (left, right) in enumerate(
                ((left, right) for left in nodes for right in nodes if left != right), 1)]


def vectors():
    policy = json.loads((HERE / "policy.json").read_text(encoding="utf-8"))
    policy_hash = "sha256:" + hashlib.sha256(jcs.canonicalize(policy)).hexdigest()
    native = json.loads((ROOT / "composed/v1/agent_interop_test_001/happy-path.json").read_text(encoding="utf-8"))
    members = [SUBJECT, "did:example:ring-b", "did:example:ring-c", "did:example:ring-d"]
    ring = mesh(members)
    spokes = [f"did:example:spoke-{i}" for i in range(1, 7)]
    hub = [receipt(index, left, right) for index, (left, right) in enumerate(
        [(SUBJECT, spoke) for spoke in spokes] + [(spoke, SUBJECT) for spoke in spokes], 1)]
    one = receipt(1, SPONSOR, SUBJECT)
    replay = [copy.deepcopy(one) for _ in range(5)]
    # Two copies change only the wrapper ID: still the same interaction.
    replay[3]["receipt_id"] = "receipt-alias-1"
    replay[4]["receipt_id"] = "receipt-alias-2"
    honest_edges = ring + [receipt(100 + index, OUTSIDE, member)
                           for index, member in enumerate(members)]
    positive = [receipt(index, SPONSOR, SUBJECT) for index in range(1, 6)]
    cases = [
        ("closed-ring", "Four identities complete twelve internal directed interactions with no consumer-admitted root inflow.",
         ring, 0, "deny", 12, 0),
        ("hub-and-spoke", "A hub and six spokes complete twelve internal interactions with no consumer-admitted root inflow.",
         hub, 0, "deny", 12, 0),
        ("replayed-receipts", "Five copies or aliases of one rooted interaction must supply only one unit, not the requested five.",
         replay, 1, "cap", 1, 4),
        ("honest-edge-cap", "Every ring member has an outside receipt, but the admitted outside root has only one available unit for this snapshot.",
         honest_edges, 1, "cap", 16, 0),
        ("sponsor-backed-control", "Five distinct interactions and a consumer-admitted sponsor with five available synthetic units support the five-unit request.",
         positive, 5, "permit", 5, 0),
    ]
    for name, description, receipts, cap, decision, unique, duplicates in cases:
        reasons = [{"deny": "no_rooted_support", "cap": "request_exceeds_rooted_cap",
                    "permit": "request_within_rooted_cap"}[decision]]
        if duplicates:
            reasons.append("duplicate_interactions_ignored")
        inputs = {
            "agentid_attestation": copy.deepcopy(native["slots"]["agentid"]),
            "aps_delegation": copy.deepcopy(native["slots"]["aps"]),
            "agentgraph_scan": copy.deepcopy(native["slots"]["agentgraph"]),
            "receipt_graph": {
                "version": "receipt-graph-v1-structural",
                "subject_did": SUBJECT,
                "policy_id": policy["policy_id"],
                "policy_hash": policy_hash,
                "requested_units": 5,
                "receipts": receipts,
            },
        }
        expected = {
            "identity_gate": "passed", "delegation_gate": "passed",
            "key_lifecycle_gate": "passed", "security_gate": "passed",
            "composite_decision": "permit", "failing_gates": [], "decisive_gate": "all_passed",
            "reasoning": "The existing native gates pass. The separate consumer receipt-graph policy produces the bounded outcome below; it does not redefine identity or authorization.",
            "receipt_graph": {
                "decision": decision, "cap_units": cap, "max_flow_units": cap,
                "unique_interactions": unique, "duplicate_interactions": duplicates,
                "reason_codes": reasons,
            },
            "consumer_decision": {
                "decision": decision, "cap_units": cap, "failing_slots": [],
                "decisive_signal": "receipt_graph",
            },
        }
        yield name, {
            "scenario": name,
            "description": description,
            "subject": {"agent_id": "agent_interop_test_001", "did": SUBJECT},
            "inputs": inputs,
            "expected_result": expected,
            "metadata": {
                "signature_alg": "Ed25519", "canonicalization": "JCS (RFC 8785)",
                "schema_version": "1.3.0", "fixture_form": "structural",
                "contributors": ["scottonchain", "hermes-agent-909", "haroldmalikfrimpong-ops"],
                "authorship": "Codex (AI), working with the scottonchain microcredit team; design follows Hermes's offer and the maintainer's issue #12 guidance.",
                "signature_verification": "not performed; metadata names the native signature family, not a signed graph artifact",
                "scope": "Synthetic consumer-policy counterexamples and control; no live-system finding or verified principal independence.",
                "native_source": "composed/v1/agent_interop_test_001/happy-path.json",
                "policy_source": "composed/adversarial/v1/policy.json",
                "source_issue": "https://github.com/haroldmalikfrimpong-ops/agentid-aps-interop/issues/12",
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare committed bytes without writing")
    args = parser.parse_args()
    failures = []
    for name, vector in vectors():
        path = DESTINATION / f"{name}.json"
        text = json.dumps(vector, indent=2, ensure_ascii=False) + "\n"
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                failures.append(path.name)
        else:
            DESTINATION.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if failures:
        print("not reproducible: " + ", ".join(failures))
        return 1
    print("five fixtures match generator" if args.check else "wrote five structural fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
