#!/usr/bin/env python3
"""
composed/v2/generate.py — reproducible generator for the composed-v2 batch.

composed-v2 is the first step of the lockstep signed form of composed-v1.
"Lockstep" means each issuer signs its OWN slot; this batch lands the AgentAvow
(formerly AgentGraph) static_analysis slot signed, and leaves the APS and AgentID
slots structural (unsigned) for aeoess and Harold to sign in their own follow-up
PRs. Only the AgentAvow slot carries a signature here.

    python3 composed/v2/generate.py        # rewrite fixtures + jwks.json
    python3 composed/v2/generate.py --check # regenerate, diff, verify sig, exit 1 on drift

AgentAvow slot signature (slots.agentgraph):
  Compact JWS (RFC 7515, EdDSA), produced by the product's real
  src/attestation/composed_slot.sign_slot_v2 over src/signing.py, signed with the
  PRODUCTION key inside the agentgraph-backend prod container. It verifies against
  the live agentgraph.co/.well-known/jwks.json entry `agentgraph-security-v1`
  (x=JwovTLVbpgk85zlMNruTiLzp85dAucsZWngs8NisBFg). The signed preimage is the v1
  *structural* slot; the emitted slot relabels version to
  "agentgraph-scan-v1-signed" and attaches the JWS + signer_key_id.

  The production private key is server-side only and is NEVER committed, so this
  script cannot re-sign locally. Instead the two distinct production JWS strings
  are embedded here as data (keyed by the slot's evidence_hash), and both
  generate.py and verify.py assert each JWS verifies against the bundled AgentAvow
  public key AND that its payload binds to the regenerated structural slot. The
  structural content is fully reproducible from source; the signature is verified,
  not regenerated. That is the reproducibility contract for a production-signed
  fixture whose key is not on this machine.

APS slot (slots.aps) and AgentID slot (slots.agentid):
  Structural (unsigned) in v2 — no signature/signer_key_id. Each co-issuer signs
  its own slot in the coordinated lockstep follow-up. The AgentID slot IS
  shape-aligned per issue #5 item (b): the v1 fixtures shipped version:"1.1.0" +
  `did`; v2 emits version:"agentid-identity-v1-structural" + `subject_did` so the
  slots share one subject vocabulary. Aligning the shape does not require a key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs  # RFC 8785 canonicalization (same lib verify.py uses)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).resolve().parent
V1_DIR = HERE.parent / "v1" / "agent_interop_test_001"
OUT_DIR = HERE / "agent_interop_test_001"
JWKS_PATH = HERE / "jwks.json"

COMPOSITION_VERSION = "composed-v2"

# AgentAvow issuer identity — unchanged by the AgentGraph -> AgentAvow rebrand.
AGENTAVOW_KID = "agentgraph-security-v1"
AGENTAVOW_SIGNER_KEY_ID = "did:web:agentgraph.co#agentgraph-security-v1"
# Public key of agentgraph-security-v1 as served at the LIVE JWKS. This is the
# offline trust anchor; it is the production public key, copied verbatim from
# https://agentgraph.co/.well-known/jwks.json .
AGENTAVOW_PUBLIC_X = "JwovTLVbpgk85zlMNruTiLzp85dAucsZWngs8NisBFg"
LIVE_JWKS_URL = "https://agentgraph.co/.well-known/jwks.json"

# Production JWS strings, keyed by the AgentAvow slot's evidence_hash. Produced by
# sign_slot_v2 with the PRODUCTION key in agentgraph-backend-1; verified below to
# bind to the reproduced structural slot and to verify under AGENTAVOW_PUBLIC_X.
PROD_AGENTGRAPH_JWS = {
    "sha256:129c1949896a126ad612d82b8bc50777ce2a712690b3c36d4f50670c8092c8eb":
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImFnZW50Z3JhcGgtc2VjdXJpdHktdjEifQ.eyJjYW5vbmljYWxpemF0aW9uX3NwZWMiOiJqY3MtcmZjODc4NStzaGEyNTYiLCJldmlkZW5jZV9oYXNoIjoic2hhMjU2OjEyOWMxOTQ5ODk2YTEyNmFkNjEyZDgyYjhiYzUwNzc3Y2UyYTcxMjY5MGIzYzM2ZDRmNTA2NzBjODA5MmM4ZWIiLCJldmlkZW5jZV91cmwiOiJodHRwczovL2FnZW50Z3JhcGguY28vYXBpL3YxL2VudGl0aWVzL2FnZW50X2ludGVyb3BfdGVzdF8wMDEvYXR0ZXN0YXRpb24vY29tcG9zZWQtc2xvdCIsImdhdGVzIjp7ImRlcGVuZGVuY3lfYXVkaXQiOnsiY3JpdGljYWwiOjAsImdyYWRlIjoiQSIsImhpZ2giOjAsInNjb3JlIjowLjg1fSwic2VjcmV0X3NjYW4iOnsiZ3JhZGUiOiJBKyIsImlzc3VlX2NvdW50IjowLCJzY29yZSI6MX0sInN0YXRpY19hbmFseXNpcyI6eyJncmFkZSI6IkEiLCJpc3N1ZV9jb3VudCI6MCwic2NvcmUiOjAuOX19LCJpc3N1ZXJfZGlkIjoiZGlkOndlYjphZ2VudGdyYXBoLmNvIiwib3ZlcmFsbF9ncmFkZSI6IkEiLCJzY2FuX3RhcmdldCI6eyJhcnRpZmFjdF9yZWYiOiJnaXQ6c2hhMjU2OjZjMGY0ZmRlYWEyZjhiNmNlMGMzZjBmNWU4YTRhOWYxYzdlNmQ1YjgiLCJmZXRjaGVkX2F0IjoiMjAyNi0wNC0xNVQxMjowMDowMFoiLCJ0eXBlIjoicmVwbyIsInVybCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9hZ2VudGdyYXBoLWNvL2ludGVyb3AtdGVzdC1hZ2VudCJ9LCJzY2FubmVkX2F0IjoiMjAyNi0wNC0xNVQxMjowMDowMFoiLCJzY2FubmVyIjp7Im5hbWUiOiJhZ2VudGdyYXBoLXRydXN0LXNjYW5uZXIiLCJ2ZXJzaW9uIjoiMjAyNi4wNC4xIn0sInN1YmplY3RfZGlkIjoiZGlkOndlYjpnZXRhZ2VudGlkLmRldjphZ2VudDphZ2VudF9pbnRlcm9wX3Rlc3RfMDAxIiwidmVyc2lvbiI6ImFnZW50Z3JhcGgtc2Nhbi12MS1zdHJ1Y3R1cmFsIn0.Fqv3hRailVrmDR-35yTO9Z9JGp-zl0DAWQxlscdIDhzAWWyrs_BGz1u04ZoK0LmeeS7TCX79pOxMl88tYgPKBw",
    "sha256:92f97d2db154429b42c851f90c70abeab8f910a2a879e203c3a616481276c71f":
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImFnZW50Z3JhcGgtc2VjdXJpdHktdjEifQ.eyJjYW5vbmljYWxpemF0aW9uX3NwZWMiOiJqY3MtcmZjODc4NStzaGEyNTYiLCJldmlkZW5jZV9oYXNoIjoic2hhMjU2OjkyZjk3ZDJkYjE1NDQyOWI0MmM4NTFmOTBjNzBhYmVhYjhmOTEwYTJhODc5ZTIwM2MzYTYxNjQ4MTI3NmM3MWYiLCJldmlkZW5jZV91cmwiOiJodHRwczovL2FnZW50Z3JhcGguY28vYXBpL3YxL2VudGl0aWVzL2FnZW50X2ludGVyb3BfdGVzdF8wMDEvYXR0ZXN0YXRpb24vY29tcG9zZWQtc2xvdCIsImdhdGVzIjp7ImRlcGVuZGVuY3lfYXVkaXQiOnsiY3JpdGljYWwiOjAsImdyYWRlIjoiQSIsImhpZ2giOjAsInNjb3JlIjowLjl9LCJzZWNyZXRfc2NhbiI6eyJncmFkZSI6IkYiLCJpc3N1ZV9jb3VudCI6MSwic2NvcmUiOjAuMTV9LCJzdGF0aWNfYW5hbHlzaXMiOnsiZ3JhZGUiOiJBIiwiaXNzdWVfY291bnQiOjAsInNjb3JlIjowLjg1fX0sImlzc3Vlcl9kaWQiOiJkaWQ6d2ViOmFnZW50Z3JhcGguY28iLCJvdmVyYWxsX2dyYWRlIjoiRCIsInNjYW5fdGFyZ2V0Ijp7ImFydGlmYWN0X3JlZiI6ImdpdDpzaGEyNTY6NmMwZjRmZGVhYTJmOGI2Y2UwYzNmMGY1ZThhNGE5ZjFjN2U2ZDViOCIsImZldGNoZWRfYXQiOiIyMDI2LTA0LTE1VDEyOjAwOjAwWiIsInR5cGUiOiJyZXBvIiwidXJsIjoiaHR0cHM6Ly9naXRodWIuY29tL2FnZW50Z3JhcGgtY28vaW50ZXJvcC10ZXN0LWFnZW50In0sInNjYW5uZWRfYXQiOiIyMDI2LTA0LTE1VDEyOjAwOjAwWiIsInNjYW5uZXIiOnsibmFtZSI6ImFnZW50Z3JhcGgtdHJ1c3Qtc2Nhbm5lciIsInZlcnNpb24iOiIyMDI2LjA0LjEifSwic3ViamVjdF9kaWQiOiJkaWQ6d2ViOmdldGFnZW50aWQuZGV2OmFnZW50OmFnZW50X2ludGVyb3BfdGVzdF8wMDEiLCJ2ZXJzaW9uIjoiYWdlbnRncmFwaC1zY2FuLXYxLXN0cnVjdHVyYWwifQ.30T2T-x4_LBHNtwYyvm5Ji_t5Xis_aXmUXUyUtsXRz1l85EMs20huo_1kFzUb6S-dzKhzdpXyQAFg1iAESuADw",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# Legacy AgentAvow JCS canonicalize — byte-for-byte mirror of src/signing.py
# canonicalize() (null-strip, integer-valued floats -> int). For the ASCII/no-null
# content in this batch it equals RFC 8785 JCS; asserted below.
def _legacy_normalize(obj):
    if isinstance(obj, dict):
        return {k: _legacy_normalize(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_legacy_normalize(x) for x in obj]
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ValueError(f"cannot canonicalize {obj}")
        if obj == int(obj):
            return int(obj)
    return obj


def _legacy_canonicalize(payload) -> bytes:
    return json.dumps(_legacy_normalize(payload), sort_keys=True, separators=(",", ":")).encode()


def _agentavow_pubkey() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(AGENTAVOW_PUBLIC_X))


def sign_agentgraph_slot(structural_slot: dict) -> dict:
    """Attach the production JWS to the structural AgentAvow slot and verify it."""
    assert structural_slot["version"] == "agentgraph-scan-v1-structural"
    ev = structural_slot["evidence_hash"]
    jws = PROD_AGENTGRAPH_JWS.get(ev)
    if jws is None:
        raise SystemExit(f"FATAL: no production JWS on file for evidence_hash {ev}")

    # Reproduce the signed preimage (structural slot minus signature) and assert
    # the JWS binds to it and verifies under the live AgentAvow public key.
    unsigned = {k: v for k, v in structural_slot.items() if k != "signature"}
    legacy = _legacy_canonicalize(unsigned)
    if legacy != jcs.canonicalize(unsigned):
        raise SystemExit("FATAL: legacy canonicalize != RFC 8785 JCS for agentgraph slot")
    h_b64, p_b64, s_b64 = jws.split(".")
    if _b64url_decode(p_b64) != legacy:
        raise SystemExit("FATAL: production JWS payload does not bind to reproduced slot")
    try:
        _agentavow_pubkey().verify(_b64url_decode(s_b64), (h_b64 + "." + p_b64).encode())
    except InvalidSignature:
        raise SystemExit("FATAL: production JWS does not verify under live AgentAvow key")

    signed = dict(structural_slot)
    signed["version"] = "agentgraph-scan-v1-signed"
    signed["signature"] = jws
    signed["signer_key_id"] = AGENTAVOW_SIGNER_KEY_ID
    return signed


def align_agentid_slot(v1_slot: dict) -> dict:
    """Shape-align per issue #5 (b): did -> subject_did, version -> structural. Unsigned."""
    aligned = dict(v1_slot)
    subject = aligned.pop("did", None) or aligned.get("subject_did")
    rebuilt = {"subject_did": subject}
    for k, v in aligned.items():
        if k == "subject_did":
            continue
        rebuilt[k] = v
    rebuilt["version"] = "agentid-identity-v1-structural"
    # explicitly structural: no signature / signer_key_id
    return rebuilt


def structural_aps_slot(v1_slot: dict) -> dict:
    """APS stays structural in v2 (unsigned). Strip any signature material."""
    slot = {k: v for k, v in v1_slot.items() if k not in ("signature", "signer_key_id")}
    chain = []
    for hop in v1_slot["delegation_chain"]:
        chain.append({k: v for k, v in hop.items() if k not in ("signature", "signer_key_id")})
    slot["delegation_chain"] = chain
    slot["delegation_chain_root"] = (
        "sha256:" + hashlib.sha256(jcs.canonicalize(chain)).hexdigest()
    )
    return slot


def build_envelope(v1_env: dict) -> dict:
    slots = v1_env["slots"]
    out_slots = {
        "agentid": align_agentid_slot(slots["agentid"]),
        "aps": structural_aps_slot(slots["aps"]),
        "agentgraph": sign_agentgraph_slot(slots["agentgraph"]),
    }
    return {
        "composition_version": COMPOSITION_VERSION,
        "subject_did": v1_env["subject_did"],
        "issued_at": v1_env["issued_at"],
        "slots": out_slots,
        "expected_composite": v1_env["expected_composite"],
        "metadata": {
            "contributors": ["kenneives"],
            "fixture_form": "partially-signed",
            "derived_from": "composed/v1/agent_interop_test_001/" + v1_env["_src_name"],
            "signed_slots": ["agentgraph"],
            "structural_slots": ["agentid", "aps"],
            "signing": {
                "agentgraph": {
                    "style": "compact-jws-rfc7515",
                    "signer_key_id": AGENTAVOW_SIGNER_KEY_ID,
                    "preimage": "JCS(RFC8785) of the v1 structural slot minus signature",
                    "key": "production (agentgraph.co); verifies against " + LIVE_JWKS_URL,
                },
                "aps": {
                    "status": "structural (unsigned) in v2",
                    "note": "aeoess signs the APS slot in the coordinated lockstep follow-up",
                },
                "agentid": {
                    "status": "structural (unsigned) in v2",
                    "shape_alignment": "issue #5 (b): did->subject_did, version->agentid-identity-v1-structural",
                    "note": "Harold signs the AgentID slot in the coordinated lockstep follow-up",
                },
            },
            "lockstep_note": (
                "Lockstep means each issuer signs its own slot. This PR lands the "
                "AgentAvow slot signed; APS (aeoess) and AgentID (Harold) sign their "
                "own slots in their follow-up PRs."
            ),
            "trust_anchor": "composed/v2/jwks.json (AgentAvow key, mirrors live " + LIVE_JWKS_URL + ")",
        },
    }


def build_jwks() -> dict:
    return {
        "_comment": (
            "Offline trust anchor for composed/v2. Contains only the AgentAvow key: "
            "agentgraph-security-v1 is the product's PRODUCTION public key, copied "
            "verbatim from " + LIVE_JWKS_URL + ". The AgentAvow slot signature in this "
            "batch verifies against it. APS and AgentID slots are structural (unsigned) "
            "in v2; their keys join this JWKS when each co-issuer signs its own slot."
        ),
        "_source": LIVE_JWKS_URL,
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": AGENTAVOW_KID,
                "x": AGENTAVOW_PUBLIC_X,
                "_signer_key_id": AGENTAVOW_SIGNER_KEY_ID,
                "_provenance": "production key, live at " + LIVE_JWKS_URL,
            }
        ],
    }


SOURCES = ("happy-path.json", "aps-revoked-delegation.json", "agentgraph-secret-leaked.json")


def _render():
    outputs = {}
    for name in SOURCES:
        v1_env = json.loads((V1_DIR / name).read_text())
        v1_env["_src_name"] = name
        outputs[name] = json.dumps(build_envelope(v1_env), indent=2, ensure_ascii=False) + "\n"
    outputs["jwks.json"] = json.dumps(build_jwks(), indent=2, ensure_ascii=False) + "\n"
    return outputs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="diff against committed files, exit 1 on drift")
    args = ap.parse_args()

    outputs = _render()  # signature binding + live-key verification happen here
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.check:
        drift = [n for n in SOURCES if not (OUT_DIR / n).exists() or (OUT_DIR / n).read_text() != outputs[n]]
        if not JWKS_PATH.exists() or JWKS_PATH.read_text() != outputs["jwks.json"]:
            drift.append("jwks.json")
        if drift:
            sys.stderr.write("DRIFT: " + ", ".join(drift) + "\n")
            return 1
        print("reproducible: committed fixtures match generator output; AgentAvow JWS verifies under live key")
        return 0

    for name in SOURCES:
        (OUT_DIR / name).write_text(outputs[name])
    JWKS_PATH.write_text(outputs["jwks.json"])
    print("wrote:", ", ".join(SOURCES), "and jwks.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
