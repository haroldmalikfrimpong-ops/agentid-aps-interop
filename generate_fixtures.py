"""Generate deterministic AgentID test fixtures for interop."""
import json
import hashlib
import base64
import sys
sys.path.insert(0, "C:/Users/harol/getagentid")
from sdk.python.agentid.ed25519 import Ed25519Identity
from sdk.python.agentid.did import create_did_aps

# Deterministic test agent from known seed — NOT a production key
seed = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
identity = Ed25519Identity.from_seed(seed)
pub_hex = identity.ed25519_public_key_hex
pub_bytes = identity.ed25519_public_key
did_aps = create_did_aps(pub_bytes)

agent_id = "agent_interop_test_001"
did_web = f"did:web:getagentid.dev:agent:{agent_id}"

print(f"Ed25519 public key: {pub_hex}")
print(f"DID (aps): {did_aps}")
print(f"DID (web): {did_web}")

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

# --- 1. Registration ---
registration = {
    "description": "Agent registration payload and response",
    "request": {
        "name": "Interop Test Agent",
        "description": "Test agent for AgentID + APS interop verification",
        "capabilities": ["verify", "sign", "delegate"],
        "platform": "test",
    },
    "response": {
        "agent_id": agent_id,
        "name": "Interop Test Agent",
        "description": "Test agent for AgentID + APS interop verification",
        "capabilities": ["verify", "sign", "delegate"],
        "trust_level": 1,
        "trust_level_label": "L1 - Registered",
        "did": did_web,
    },
}
with open("fixtures/agentid/registration.json", "w") as f:
    json.dump(registration, f, indent=2)
print("Written: registration.json")

# --- 2. Ed25519 Binding ---
binding_message = f"AgentID:bind-ed25519:{agent_id}:{pub_hex}".encode()
binding_sig = identity.sign(binding_message)

ed25519_binding = {
    "description": "Ed25519 key binding - agent proves possession of private key",
    "agent_id": agent_id,
    "ed25519_public_key": pub_hex,
    "solana_address": identity.solana_address,
    "binding_message": binding_message.decode(),
    "binding_signature": binding_sig.hex(),
    "verification": {
        "algorithm": "Ed25519",
        "public_key": pub_hex,
        "message": binding_message.decode(),
        "signature": binding_sig.hex(),
        "expected": True,
    },
    "post_binding": {
        "trust_level": 2,
        "trust_level_label": "L2 - Verified",
        "supported_key_types": ["ecdsa-p256", "ed25519"],
    },
}
with open("fixtures/agentid/ed25519-binding.json", "w") as f:
    json.dump(ed25519_binding, f, indent=2)
print("Written: ed25519-binding.json")

# --- 3. Trust Header JWT ---
header = {"alg": "EdDSA", "typ": "Agent-Trust-Score", "kid": "agentid-interop-test"}
payload = {
    "agent_id": agent_id,
    "did": did_web,
    "trust_level": 2,
    "trust_level_label": "L2 - Verified",
    "behavioural_risk_score": 0,
    "scarring_score": 0,
    "context_continuity_score": 100,
    "attestation_count": 1,
    "iat": 1744156800,
    "exp": 1744160400,
}

header_b64 = b64url(header)
payload_b64 = b64url(payload)
signing_input = f"{header_b64}.{payload_b64}".encode()
jwt_sig = identity.sign(signing_input)
jwt_sig_b64 = base64.urlsafe_b64encode(jwt_sig).rstrip(b"=").decode()
jwt_token = f"{header_b64}.{payload_b64}.{jwt_sig_b64}"

trust_header = {
    "description": "Signed Agent-Trust-Score JWT (EdDSA) for HTTP header injection",
    "jwt": jwt_token,
    "header": header,
    "payload": payload,
    "signing_input": signing_input.decode(),
    "signature_hex": jwt_sig.hex(),
    "verification": {"algorithm": "EdDSA", "public_key": pub_hex, "expected": True},
}
with open("fixtures/agentid/trust-header.json", "w") as f:
    json.dump(trust_header, f, indent=2)
print("Written: trust-header.json")

# --- 4. DID Document ---
did_document = {
    "description": "W3C DID Document for the test agent",
    "did_document": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did_web,
        "verificationMethod": [
            {
                "id": f"{did_web}#ed25519-key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did_web,
                "publicKeyHex": pub_hex,
            }
        ],
        "authentication": [f"{did_web}#ed25519-key-1"],
        "assertionMethod": [f"{did_web}#ed25519-key-1"],
        "service": [
            {
                "id": f"{did_web}#agentid-verify",
                "type": "AgentIDVerification",
                "serviceEndpoint": "https://getagentid.dev/api/v1/agents/verify",
            },
            {
                "id": f"{did_web}#trust-header",
                "type": "AgentTrustHeader",
                "serviceEndpoint": "https://getagentid.dev/api/v1/agents/trust-header",
            },
        ],
    },
    "also_resolvable_as": {
        "did_aps": did_aps,
        "note": "Same Ed25519 key, multibase-encoded (base58btc)",
    },
}
with open("fixtures/agentid/did-document.json", "w") as f:
    json.dump(did_document, f, indent=2)
print("Written: did-document.json")

# --- 5. Verify Response ---
credential_fields = json.dumps(
    {"agent_id": agent_id, "did": did_web, "trust_level": 2, "ed25519_key": pub_hex},
    sort_keys=True,
    separators=(",", ":"),
)
credential_hash = hashlib.sha256(credential_fields.encode()).hexdigest()

verify_response = {
    "description": "Full verification response from AgentID verify endpoint",
    "request": {"agent_id": agent_id},
    "response": {
        "verified": True,
        "agent_id": agent_id,
        "did": did_web,
        "resolution_source": "direct",
        "name": "Interop Test Agent",
        "capabilities": ["verify", "sign", "delegate"],
        "trust_level": 2,
        "trust_level_label": "L2 - Verified",
        "permissions": [
            "read", "discover", "verify", "send_message",
            "connect", "challenge_response", "handle_data",
        ],
        "certificate_valid": True,
        "active": True,
        "supported_key_types": ["ecdsa-p256", "ed25519"],
        "negative_signals": 0,
        "scarring_score": 0,
    },
    "credential_hash": credential_hash,
    "credential_hash_input": credential_fields,
    "credential_hash_note": "SHA-256 of canonicalized credential fields - use this in APS receipt chain",
}
with open("fixtures/agentid/verify-response.json", "w") as f:
    json.dump(verify_response, f, indent=2)
print("Written: verify-response.json")

# --- 6. APS placeholder ---
aps_placeholder = {
    "description": "Placeholder for APS delegation and receipt fixtures",
    "contributed_by": "@aeoess",
    "expected_fixtures": [
        "delegation.json - delegation scope evaluation referencing AgentID credential",
        "receipt.json - governance receipt with credential_hash from AgentID",
    ],
    "agentid_credential_hash": credential_hash,
    "note": "APS fixtures should reference this credential_hash to complete the audit chain",
}
with open("fixtures/aps/README.json", "w") as f:
    json.dump(aps_placeholder, f, indent=2)
print("Written: aps/README.json")

# --- 7. Cross-chain test ---
cross_chain = {
    "description": "End-to-end test: identity -> authorization -> receipt",
    "steps": [
        {
            "step": 1,
            "layer": "Identity (AgentID)",
            "action": "Verify agent via DID",
            "input": {"did": did_web},
            "expected": {"verified": True, "trust_level": 2, "ed25519_key": pub_hex},
        },
        {
            "step": 2,
            "layer": "Identity (AgentID)",
            "action": "Verify trust-header JWT signature",
            "input": {"jwt": jwt_token, "public_key": pub_hex},
            "expected": {"signature_valid": True, "algorithm": "EdDSA"},
        },
        {
            "step": 3,
            "layer": "Authorization (APS)",
            "action": "Evaluate delegation scope using AgentID credential",
            "input": {
                "credential_hash": credential_hash,
                "requested_scope": "tool:web_search",
            },
            "expected": "TO BE PROVIDED BY @aeoess",
        },
        {
            "step": 4,
            "layer": "Receipt (APS)",
            "action": "Governance receipt references AgentID credential hash",
            "input": {"action_ref": "cross-chain-test-001"},
            "expected": "TO BE PROVIDED BY @aeoess",
        },
    ],
    "test_agent": {
        "agent_id": agent_id,
        "did_web": did_web,
        "did_aps": did_aps,
        "ed25519_public_key": pub_hex,
        "credential_hash": credential_hash,
    },
}
with open("fixtures/cross-chain/identity-to-receipt.json", "w") as f:
    json.dump(cross_chain, f, indent=2)
print("Written: cross-chain/identity-to-receipt.json")

print("\nAll fixtures generated successfully. No production keys used.")
print(f"Credential hash for APS reference: {credential_hash}")
