#!/usr/bin/env python3
"""
composed/v2/sign_agentid_slot.py — issuer-side signer for the AgentID slot.

Run by the AgentID issuer ONLY. The production Ed25519 seed (kid `agentid-2026-03`)
is read from the AGENTID_ED25519_PRIVATE_KEY environment variable (base64url, 32
bytes) and is never written anywhere. The output is a compact JWS (RFC 7515, EdDSA)
whose payload is RFC 8785 JCS of the *structural* AgentID slot
(`version: agentid-identity-v1-structural`), exactly mirroring how the AgentAvow
slot is signed in this batch. The JWS string is then embedded in generate.py as
data, keyed by sha256(JCS(structural slot)), so third parties verify (never
regenerate) the signature — same reproducibility contract as the AgentAvow slot.

    AGENTID_ED25519_PRIVATE_KEY=... python3 composed/v2/sign_agentid_slot.py composed/v1/agent_interop_test_001/happy-path.json

Prints: payload hash, JWS, and a self-verification against the LIVE JWKS entry.
Refuses to sign if the derived public key is not the live `agentid-2026-03` key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from generate import align_agentid_slot, AGENTID_KID, AGENTID_PUBLIC_X, LIVE_AGENTID_JWKS_URL  # noqa: E402


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    seed_b64 = os.environ.get("AGENTID_ED25519_PRIVATE_KEY")
    if not seed_b64:
        sys.stderr.write("AGENTID_ED25519_PRIVATE_KEY not set\n")
        return 2
    seed = _b64url_decode(seed_b64)
    if len(seed) != 32:
        sys.stderr.write("seed must be 32 bytes\n")
        return 2
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    derived_x = _b64url(pub_raw)
    if derived_x != AGENTID_PUBLIC_X:
        sys.stderr.write(f"REFUSING: derived public key {derived_x} != {AGENTID_KID} ({AGENTID_PUBLIC_X})\n")
        return 1
    live = json.loads(urllib.request.urlopen(LIVE_AGENTID_JWKS_URL, timeout=15).read().decode())
    live_x = next((k["x"] for k in live["keys"] if k.get("kid") == AGENTID_KID), None)
    if live_x != AGENTID_PUBLIC_X:
        sys.stderr.write(f"REFUSING: live JWKS {AGENTID_KID} x={live_x} != pinned {AGENTID_PUBLIC_X}\n")
        return 1

    v1_env = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    structural = align_agentid_slot(v1_env["slots"]["agentid"])
    assert structural["version"] == "agentid-identity-v1-structural"
    payload = jcs.canonicalize(structural)
    header = json.dumps({"alg": "EdDSA", "kid": AGENTID_KID}, separators=(",", ":")).encode()
    signing_input = _b64url(header) + "." + _b64url(payload)
    sig = priv.sign(signing_input.encode())
    jws = signing_input + "." + _b64url(sig)
    priv.public_key().verify(sig, signing_input.encode())  # self-check
    print("payload_sha256:", hashlib.sha256(payload).hexdigest())
    print("jws:", jws)
    print("verified against live", AGENTID_KID)
    return 0


if __name__ == "__main__":
    sys.exit(main())
