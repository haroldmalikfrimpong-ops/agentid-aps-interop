"""Independent-oracle and mutation tests for the optional graph policy."""

import copy
import itertools
import json
import random
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import ValidationError

import verify


def fixture(name):
    return json.loads((verify.FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def verify_vector(vector):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "vector.json"
        path.write_text(json.dumps(vector), encoding="utf-8")
        return verify.verify_fixture(path)


class GraphPolicyTests(unittest.TestCase):
    def test_five_decisions_match_hand_specified_oracle_without_network(self):
        expected = {"closed-ring": ("deny", 0), "hub-and-spoke": ("deny", 0),
                    "replayed-receipts": ("cap", 1), "honest-edge-cap": ("cap", 1),
                    "sponsor-backed-control": ("permit", 5)}
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network used")):
            for name, outcome in expected.items():
                with self.subTest(name=name):
                    result = verify.evaluate(fixture(name))["consumer_composite"]
                    self.assertEqual((result["decision"], result["cap_units"]), outcome)

    def test_expected_block_cannot_influence_evaluation(self):
        vector = fixture("closed-ring")
        vector["expected_result"] = {"decision": "permit", "cap_units": 1000000}
        vector["scenario"] = "sponsor-backed-control"
        result = verify.evaluate(vector)["consumer_composite"]
        self.assertEqual((result["decision"], result["cap_units"]), ("deny", 0))

    def test_oracle_corruption_is_reported(self):
        vector = fixture("closed-ring")
        vector["expected_result"]["consumer_decision"]["decision"] = "permit"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.json"
            path.write_text(json.dumps(vector), encoding="utf-8")
            _, checks, _ = verify.verify_fixture(path)
        self.assertIn(("consumer decision", False), checks)

    def test_each_native_oracle_corruption_is_reported(self):
        mutations = {
            "identity_gate": "failed", "key_lifecycle_gate": "revoked",
            "delegation_gate": "failed", "security_gate": "failed",
            "wallet_state_gate": "passed", "revocation_gate": "passed", "policy_gate": "passed",
            "composite_decision": "deny", "failing_gates": ["identity_gate"],
            "decisive_gate": "identity",
        }
        for field, wrong_value in mutations.items():
            vector = fixture("sponsor-backed-control")
            vector["expected_result"][field] = wrong_value
            with self.subTest(field=field):
                _, checks, result = verify_vector(vector)
                label = "native decision" if field == "composite_decision" else field
                self.assertIn((label, False), checks)
                self.assertEqual(result["native_composite"]["decision"], "permit")
                self.assertEqual(result["consumer_composite"]["cap_units"], 5)

    def test_required_oracles_cannot_be_removed_or_unrecognized(self):
        required = ["identity_gate", "key_lifecycle_gate", "delegation_gate", "security_gate",
                    "decisive_gate", "receipt_graph", "consumer_decision"]
        for field in required:
            vector = fixture("sponsor-backed-control")
            del vector["expected_result"][field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                verify_vector(vector)
        vector = fixture("sponsor-backed-control")
        vector["expected_result"]["unsupported_gate"] = "passed"
        with self.assertRaises(ValidationError):
            verify_vector(vector)

    def test_native_denial_oracles_match_input_diagnostics(self):
        cases = [
            ("certificate", ("agentid_attestation", "certificate_valid"), False,
             {"identity_gate": "failed"}, "agentid", "identity"),
            ("deprecated", ("agentid_attestation", "key_status"), "deprecated",
             {"key_lifecycle_gate": "deprecated"}, "agentid", "key_lifecycle"),
            ("revoked", ("agentid_attestation", "key_status"), "revoked",
             {"key_lifecycle_gate": "revoked"}, "agentid", "key_lifecycle"),
            ("compromised", ("agentid_attestation", "key_status"), "compromised",
             {"key_lifecycle_gate": "compromised"}, "agentid", "key_lifecycle"),
            ("revocation_timestamp", ("agentid_attestation", "revoked_at"), "2026-04-21T00:00:00Z",
             {"key_lifecycle_gate": "revoked"}, "agentid", "key_lifecycle"),
            ("delegation", ("aps_delegation", "delegation_chain", 0, "revoked_at"), "2026-04-21T00:00:00Z",
             {"delegation_gate": "failed"}, "aps", "delegation"),
            ("security", ("agentgraph_scan", "gates", "static_analysis", "grade"), "F",
             {"security_gate": "failed"}, "agentgraph", "security"),
        ]
        for name, path, value, gate_changes, slot, decisive in cases:
            vector = fixture("sponsor-backed-control")
            target = vector["inputs"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            aps = vector["inputs"]["aps_delegation"]
            aps["delegation_chain_root"] = verify.digest(aps["delegation_chain"])
            expected = vector["expected_result"]
            expected.update(gate_changes)
            expected.update({"composite_decision": "deny", "failing_gates": list(gate_changes),
                             "decisive_gate": decisive, "wallet_state_gate": "not_applicable",
                             "revocation_gate": "not_applicable", "policy_gate": "not_applicable"})
            expected["consumer_decision"] = {"decision": "deny", "cap_units": 0,
                                             "failing_slots": [slot], "decisive_signal": slot}
            with self.subTest(name=name):
                _, checks, result = verify_vector(vector)
                self.assertTrue(all(ok for _, ok in checks), checks)
                self.assertEqual(result["slots"]["receipt_graph"]["cap_units"], 5)

    def test_aliases_and_reordering_do_not_increase_capacity(self):
        vector = fixture("replayed-receipts")
        graph = vector["inputs"]["receipt_graph"]
        original = copy.deepcopy(graph["receipts"][0])
        graph["receipts"] = [{**original, "receipt_id": f"alias-{i}"} for i in range(100)]
        random.Random(7).shuffle(graph["receipts"])
        result = verify.evaluate(vector)["slots"]["receipt_graph"]
        self.assertEqual((result["cap_units"], result["unique_interactions"], result["duplicate_interactions"]),
                         (1, 1, 99))

    def test_conflicting_replay_fails_closed(self):
        vector = fixture("replayed-receipts")
        vector["inputs"]["receipt_graph"]["receipts"][1]["worker_did"] = "did:example:other"
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            verify.evaluate(vector)

    def test_caller_cannot_inject_a_root_or_select_another_policy(self):
        vector = fixture("closed-ring")
        graph = vector["inputs"]["receipt_graph"]
        graph["roots"] = [{"did": vector["subject"]["did"], "available_units": 1000}]
        with self.assertRaises(Exception):
            verify.evaluate(vector)
        graph.pop("roots")
        graph["policy_hash"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "consumer-selected policy"):
            verify.evaluate(vector)

    def test_graph_support_never_overrides_native_denial(self):
        vector = fixture("sponsor-backed-control")
        vector["inputs"]["aps_delegation"]["delegation_chain"][0]["revoked_at"] = "2026-04-21T00:00:00Z"
        aps = vector["inputs"]["aps_delegation"]
        aps["delegation_chain_root"] = verify.digest(aps["delegation_chain"])
        result = verify.evaluate(vector)
        self.assertEqual(result["slots"]["receipt_graph"]["cap_units"], 5)
        self.assertEqual(result["consumer_composite"],
                         {"decision": "deny", "cap_units": 0, "failing_slots": ["aps"], "decisive_signal": "aps"})

    def test_subject_hash_and_missing_native_state_rejected(self):
        for change in ("subject", "chain", "missing"):
            vector = fixture("sponsor-backed-control")
            if change == "subject":
                vector["inputs"]["receipt_graph"]["subject_did"] = "did:example:other"
            elif change == "chain":
                vector["inputs"]["aps_delegation"]["delegation_chain_root"] = "sha256:" + "0" * 64
            else:
                del vector["inputs"]["agentid_attestation"]["certificate_valid"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify.evaluate(vector)

    def test_flow_equals_independent_exhaustive_min_cut(self):
        # An independent cut enumeration catches residual/antiparallel-edge bugs.
        rng = random.Random(209)
        nodes = ["did:example:root", "did:example:a", "did:example:b", "did:example:target"]
        roots = [{"did": nodes[0], "available_units": 3}]
        for trial in range(40):
            receipts = [{"requester_did": a, "worker_did": b}
                        for a in nodes for b in nodes if a != b
                        for _ in range(rng.randrange(3))]
            cuts = []
            for flags in itertools.product((False, True), repeat=3):
                source_side = {node for node, inside in zip(nodes[:-1], flags) if inside}
                cut = 0 if nodes[0] in source_side else 3
                cut += sum(r["requester_did"] in source_side and r["worker_did"] not in source_side
                           for r in receipts)
                cuts.append(cut)
            with self.subTest(trial=trial):
                self.assertEqual(verify.max_flow_to_subject(receipts, roots, nodes[-1]), min(cuts))

    def test_large_closed_mesh_and_hub_still_have_zero_support(self):
        nodes = [f"did:example:ring-{i}" for i in range(12)]
        mesh = [{"requester_did": a, "worker_did": b} for a in nodes for b in nodes if a != b]
        spokes = [f"did:example:spoke-{i}" for i in range(30)]
        hub = [{"requester_did": a, "worker_did": b}
               for a, b in [(nodes[0], x) for x in spokes] + [(x, nodes[0]) for x in spokes]]
        for graph in (mesh, hub):
            self.assertEqual(verify.max_flow_to_subject(graph, verify.load_policy()["roots"], nodes[0]), 0)


if __name__ == "__main__":
    unittest.main()
