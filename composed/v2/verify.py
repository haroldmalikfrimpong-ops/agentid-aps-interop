#!/usr/bin/env python3
"""
composed/v2/verify.py — cross-issuer validator for the composed-v2 batch.

composed-v2 carries two production-signed slots — AgentAvow (formerly AgentGraph)
static_analysis (#11) and AgentID identity (interop-freeze-2026-10-06) — while the
APS slot rides structural (unsigned) pending aeoess's own lockstep follow-up
("lockstep" = each issuer signs its own slot). This validator:

  * runs every structural check composed/v1 ran, for all three slots;
  * verifies the AgentAvow slot's real Ed25519/JWS signature against the AgentAvow
    key in composed/v2/jwks.json (PRODUCTION key, copied verbatim from
    https://agentgraph.co/.well-known/jwks.json), and re-binds the JWS payload to
    the slot content;
  * verifies the AgentID slot's real Ed25519/JWS signature against the AgentID key
    in composed/v2/jwks.json (PRODUCTION key `agentid-2026-03`, copied verbatim from
    https://getagentid.dev/.well-known/jwks.json — the same key is
    did:web:getagentid.dev#agentid-2026-03), re-binds the payload to RFC 8785 JCS
    of the structural slot, and checks the signed subject_did matches the envelope;
  * runs negative self-tests: tampering either signed slot (content flip and
    signature flip) MUST make its signature verification fail.

It is issuer-neutral and has no dependency on any issuer SDK.

Dependencies:  pip install jcs cryptography
Exit code:     0 all fixtures pass (incl. AgentAvow + AgentID tamper rejection); 1 otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import jcs
except ImportError:
    sys.stderr.write("ERROR: jcs not installed. Run: pip install jcs\n")
    sys.exit(2)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write("ERROR: cryptography not installed. Run: pip install cryptography\n")
    sys.exit(2)

HERE = Path(__file__).resolve().parent

GATING_SLOTS = ("agentid", "aps", "agentgraph")

# v2 slot versions: AgentAvow + AgentID are signed; APS rides structural.
SLOT_EXPECTED_VERSIONS = {
    "agentgraph": {"agentgraph-scan-v1-signed"},
    "aps": {"aps-v2-structural"},
    "agentid": {"agentid-identity-v1-signed"},
}

AGENTID_KID = "agentid-2026-03"
AGENTID_SIGNER_KEY_ID = "did:web:getagentid.dev#agentid-2026-03"


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _legacy_normalize(obj):
    """Mirror of src/signing.py canonicalize(): strip nulls, int-valued floats -> int."""
    if isinstance(obj, dict):
        return {k: _legacy_normalize(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_legacy_normalize(x) for x in obj]
    if isinstance(obj, float):
        if obj == int(obj):
            return int(obj)
    return obj


def _legacy_canonicalize(payload) -> bytes:
    return json.dumps(_legacy_normalize(payload), sort_keys=True, separators=(",", ":")).encode()


def load_jwks() -> Dict[str, Ed25519PublicKey]:
    data = json.loads((HERE / "jwks.json").read_text(encoding="utf-8"))
    out: Dict[str, Ed25519PublicKey] = {}
    for jwk in data.get("keys", []):
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            out[jwk["kid"]] = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
    return out


def _kid_of(signer_key_id: Optional[str]) -> Optional[str]:
    if not signer_key_id:
        return None
    return signer_key_id.split("#", 1)[-1] if "#" in signer_key_id else signer_key_id


def verify_agentgraph_sig(slot: Dict[str, Any], jwks: Dict[str, Ed25519PublicKey]) -> bool:
    """AgentAvow compact JWS: verify Ed25519 signature + bind payload to slot content."""
    try:
        pub = jwks.get(_kid_of(slot.get("signer_key_id")))
        if pub is None:
            return False
        h_b64, p_b64, s_b64 = slot.get("signature", "").split(".")
        # 1. cryptographic authenticity over the attached payload
        pub.verify(_b64url_decode(s_b64), (h_b64 + "." + p_b64).encode())
        # 2. bind: recompute the structural preimage (version reverted, sig fields removed)
        structural = {k: v for k, v in slot.items() if k not in ("signature", "signer_key_id")}
        structural["version"] = "agentgraph-scan-v1-structural"
        expected = _legacy_canonicalize(structural)
        if _b64url_decode(p_b64) != expected:
            return False
        # 3. the jcs-rfc8785+sha256 label must hold for this content
        if expected != jcs.canonicalize(structural):
            return False
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def verify_agentid_sig(slot: Dict[str, Any], jwks: Dict[str, Ed25519PublicKey],
                       envelope_subject: Optional[str] = None) -> bool:
    """AgentID compact JWS: Ed25519 over header.payload; payload == JCS(structural slot)."""
    try:
        if slot.get("signer_key_id") != AGENTID_SIGNER_KEY_ID:
            return False
        pub = jwks.get(_kid_of(slot.get("signer_key_id")))
        if pub is None:
            return False
        h_b64, p_b64, s_b64 = slot.get("signature", "").split(".")
        header = json.loads(_b64url_decode(h_b64))
        if header != {"alg": "EdDSA", "kid": AGENTID_KID}:
            return False
        # 1. cryptographic authenticity over the attached payload
        pub.verify(_b64url_decode(s_b64), (h_b64 + "." + p_b64).encode())
        # 2. bind: payload must equal RFC 8785 JCS of the structural slot
        #    (signature fields removed, version reverted); nulls are kept — pure JCS.
        structural = {k: v for k, v in slot.items() if k not in ("signature", "signer_key_id")}
        structural["version"] = "agentid-identity-v1-structural"
        if _b64url_decode(p_b64) != jcs.canonicalize(structural):
            return False
        # 3. the signed subject must be the envelope subject
        signed = json.loads(_b64url_decode(p_b64))
        if envelope_subject is not None and signed.get("subject_did") != envelope_subject:
            return False
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _slot_passes(slot: Dict[str, Any], slot_name: str) -> bool:
    if slot_name == "agentid":
        return (
            slot.get("key_status", "active") == "active"
            and slot.get("certificate_valid", True) is True
            and slot.get("revoked_at") is None
        )
    if slot_name == "aps":
        chain = slot.get("delegation_chain", [])
        if not chain:
            return False
        if any(h.get("revoked_at") for h in chain):
            return False
        for i in range(1, len(chain)):
            parent = set(chain[i - 1].get("scope", []))
            child = set(chain[i].get("scope", []))
            if not child.issubset(parent):
                return False
        return True
    if slot_name == "agentgraph":
        gates = slot.get("gates", {})
        for g in ("static_analysis", "secret_scan", "dependency_audit"):
            gd = gates.get(g)
            if not gd or gd.get("grade") == "F":
                return False
        if gates.get("dependency_audit", {}).get("critical", 0) > 0:
            return False
        return True
    raise ValueError(slot_name)


def _recompute_chain_root(chain: List[Dict[str, Any]]) -> str:
    structural = [
        {k: v for k, v in h.items() if k not in ("signature", "signer_key_id")}
        for h in chain
    ]
    return "sha256:" + hashlib.sha256(jcs.canonicalize(structural)).hexdigest()


def _flip_last_b64(sig: str) -> str:
    last = sig[-1]
    return sig[:-1] + ("B" if last != "B" else "C")


def _negative_rows(slots: Dict[str, Any], jwks: Dict[str, Ed25519PublicKey]) -> List[Tuple[str, bool]]:
    """Tamper each signed slot (AgentAvow, AgentID) and assert verification fails."""
    import copy
    rows: List[Tuple[str, bool]] = []
    ag = copy.deepcopy(slots["agentgraph"])
    ag["gates"]["static_analysis"]["grade"] = "F"
    rows.append(("tamper rejected: agentgraph gate grade flip", not verify_agentgraph_sig(ag, jwks)))
    ag2 = copy.deepcopy(slots["agentgraph"])
    ag2["signature"] = _flip_last_b64(ag2["signature"])
    rows.append(("tamper rejected: agentgraph JWS signature flip", not verify_agentgraph_sig(ag2, jwks)))
    if "agentid" in slots:
        ai = copy.deepcopy(slots["agentid"])
        ai["trust_level"] = 4
        rows.append(("tamper rejected: agentid trust_level flip", not verify_agentid_sig(ai, jwks)))
        ai2 = copy.deepcopy(slots["agentid"])
        ai2["key_status"] = "revoked"
        rows.append(("tamper rejected: agentid key_status flip", not verify_agentid_sig(ai2, jwks)))
        ai3 = copy.deepcopy(slots["agentid"])
        ai3["signature"] = _flip_last_b64(ai3["signature"])
        rows.append(("tamper rejected: agentid JWS signature flip", not verify_agentid_sig(ai3, jwks)))
        ai4 = copy.deepcopy(slots["agentid"])
        ai4["signer_key_id"] = "did:web:agentgraph.co#agentgraph-security-v1"
        rows.append(("tamper rejected: agentid signed under a foreign kid", not verify_agentid_sig(ai4, jwks)))
    return rows


def verify_envelope(path: Path, jwks: Dict[str, Ed25519PublicKey]) -> Tuple[str, List[Tuple[str, bool]]]:
    rows: List[Tuple[str, bool]] = []
    env = json.loads(path.read_text(encoding="utf-8"))

    rows.append(("composition_version=='composed-v2'", env.get("composition_version") == "composed-v2"))
    env_subject = env.get("subject_did")
    rows.append(("subject_did present", env_subject is not None))

    slots = env.get("slots", {})
    for s in GATING_SLOTS:
        rows.append((f"slots.{s} present", s in slots))

    # subject-DID binding (all slots carry subject_did in v2 — agentid is aligned)
    for s in GATING_SLOTS:
        if s in slots:
            rows.append((f"slots.{s} subject_did == envelope subject_did",
                         slots[s].get("subject_did") == env_subject))

    # agentid no longer carries a bare `did` (shape alignment #5 (b))
    if "agentid" in slots:
        rows.append(("slots.agentid aligned: uses subject_did, no bare `did`",
                     "did" not in slots["agentid"] and "subject_did" in slots["agentid"]))

    # version strings
    for s, expected in SLOT_EXPECTED_VERSIONS.items():
        if s in slots:
            rows.append((f"slots.{s}.version in {sorted(expected)}",
                         slots[s].get("version") in expected))

    # APS is the only structural slot left in v2 (no signature material)
    for s in ("aps",):
        if s in slots:
            has_sig = "signature" in slots[s] or "signer_key_id" in slots[s] or any(
                "signature" in h for h in slots[s].get("delegation_chain", [])
            )
            rows.append((f"slots.{s} is structural (no signature) in v2", not has_sig))

    # APS delegation_chain_root over the structural chain
    if "aps" in slots:
        aps = slots["aps"]
        rows.append(("aps delegation_chain_root matches JCS+SHA256 over structural chain",
                     aps.get("delegation_chain_root") == _recompute_chain_root(aps.get("delegation_chain", []))))

    # each slot JCS-canonicalizes
    for s in GATING_SLOTS:
        if s in slots:
            try:
                jcs.canonicalize(slots[s])
                rows.append((f"slots.{s} JCS-canonicalizes", True))
            except Exception:
                rows.append((f"slots.{s} JCS-canonicalizes", False))

    # --- v2 signature verification (AgentAvow + AgentID) ---
    if "agentgraph" in slots:
        rows.append(("slots.agentgraph Ed25519/JWS signature verifies against live agentgraph.co key",
                     verify_agentgraph_sig(slots["agentgraph"], jwks)))
    if "agentid" in slots:
        rows.append(("slots.agentid Ed25519/JWS signature verifies against live getagentid.dev key "
                     "(kid agentid-2026-03) and binds to JCS(structural slot) + envelope subject",
                     verify_agentid_sig(slots["agentid"], jwks, env_subject)))
        rows.append(("slots.agentid signer_key_id == did:web:getagentid.dev#agentid-2026-03",
                     slots["agentid"].get("signer_key_id") == AGENTID_SIGNER_KEY_ID))

    # composite decision (unchanged rule from v1)
    passes = {s: _slot_passes(slots[s], s) for s in GATING_SLOTS if s in slots}
    all_pass = all(passes.values())
    expected_decision = env.get("expected_composite", {}).get("decision")
    computed = "permit" if all_pass else "deny"
    rows.append((f"expected decision '{expected_decision}' matches naive rule '{computed}'",
                 expected_decision == computed))
    declared_failing = set(env.get("expected_composite", {}).get("failing_slots", []))
    computed_failing = {s for s, ok in passes.items() if not ok}
    rows.append((f"failing_slots match (declared {sorted(declared_failing)} vs computed {sorted(computed_failing)})",
                 declared_failing == computed_failing))

    # negative self-test on the signed slot
    rows.extend(_negative_rows(slots, jwks))

    return path.name, rows


def main() -> int:
    jwks = load_jwks()
    if not jwks:
        sys.stderr.write("ERROR: no Ed25519 keys loaded from jwks.json\n")
        return 2
    if AGENTID_KID not in jwks:
        sys.stderr.write("ERROR: jwks.json has no agentid-2026-03 key\n")
        return 2

    fixtures_dir = HERE / "agent_interop_test_001"
    paths = sorted(fixtures_dir.glob("*.json"))
    if not paths:
        sys.stderr.write(f"ERROR: no composed fixtures under {fixtures_dir}\n")
        return 2

    total = passed = 0
    failing_fixtures = []
    for p in paths:
        name, rows = verify_envelope(p, jwks)
        print(f"\n== {name} ==")
        ok_all = True
        for label, ok in rows:
            total += 1
            if ok:
                passed += 1
                print(f"  PASS  {label}")
            else:
                ok_all = False
                print(f"  FAIL  {label}")
        if not ok_all:
            failing_fixtures.append(name)

    print("\n== summary ==")
    print(f"  fixtures examined: {len(paths)}")
    print(f"  checks passed:     {passed}/{total}")
    print(f"  fixtures clean:    {len(paths) - len(failing_fixtures)}/{len(paths)}")
    if failing_fixtures:
        print(f"  FAILURES in:       {', '.join(failing_fixtures)}")
        return 1
    print("  status:            OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
