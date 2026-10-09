# Adversarial receipt-graph vectors

These five structural fixtures answer the maintainer's accepted
[issue #12 proposal](https://github.com/haroldmalikfrimpong-ops/agentid-aps-interop/issues/12#issuecomment-6007115538).
Each file has the repository's existing `scenario`, `subject`, `inputs`,
`expected_result`, and `metadata` shape. `inputs` includes the composed native
receipts and a separate receipt graph. The schema additions are optional, so
older vectors and their meaning remain valid.

| Vector | Native gates | Requested synthetic units | Consumer outcome |
| --- | --- | ---: | --- |
| `closed-ring.json` | permit | 5 | deny, cap 0 |
| `hub-and-spoke.json` | permit | 5 | deny, cap 0 |
| `replayed-receipts.json` | permit | 5 | cap 1; five wrappers are one interaction |
| `honest-edge-cap.json` | permit | 5 | cap 1; outside evidence does not multiply its root budget |
| `sponsor-backed-control.json` | permit | 5 | permit, cap 5 |

`expected_result.composite_decision` retains its existing meaning: the native
identity, authorization, and security gates. The separate `receipt_graph` and
`consumer_decision` blocks specify the opt-in risk signal and its final bounded
consumer outcome. A graph denial therefore leaves `failing_gates` empty: no
identity or authorization failure has been invented.

The first case contains four mutually interacting identities. The hub case has
six spokes. The regression suite also checks a 12-member full mesh and a
30-spoke hub, without claiming a run against INAM or another live system.

## Run and reproduce

From the repository root, with Python 3.9+ and the existing `jcs` dependency plus
`jsonschema` installed:

```bash
python3 composed/adversarial/v1/verify.py
python3 composed/adversarial/v1/verify.py --json
python3 -m unittest discover -s composed/adversarial/v1 -p 'test_*.py' -v
python3 composed/adversarial/v1/generate.py --check
```

The verifier performs no network requests and checks the committed expected
decisions against independently computed results. The generator copies the
native slots from the existing composed-v1 happy-path fixture and uses fixed
inputs and hand-specified expected outcomes; it does not call the evaluator.
Running the generator without `--check` reproduces these five files only.

All dates are a fixed historical fixture snapshot. An identity passing here
does not imply its certificate is current today. These are unsigned structural
receipts; `metadata.signature_alg` identifies the native slot's algorithm
family, not evidence that a graph receipt was signed or verified.

See the [composition policy and its limits](../../../composed/adversarial/v1/README.md).

## Attribution

Codex (AI), working with the scottonchain microcredit team, authored this
implementation. Hermes (`hermes-agent-909`) proposed the attack-swap contribution.
The maintainer (`haroldmalikfrimpong-ops`) specified the fixture shape, offline
outcome checks, benign control, and separate graph signal. The native slot
fixtures retain their original AgentID, APS, and AgentGraph attribution.
