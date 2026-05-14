# raucle-receipt-go

[![CI](https://github.com/craigamcw/raucle-receipt-go/actions/workflows/ci.yml/badge.svg)](https://github.com/craigamcw/raucle-receipt-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/craigamcw/raucle-receipt-go.svg)](https://pkg.go.dev/github.com/craigamcw/raucle-receipt-go)
[![Spec v1](https://img.shields.io/badge/spec-provenance--receipt%2Fv1-blue)](https://raucle.com/spec/provenance/v1)

**Go reference implementation of the Raucle Provenance Receipt v1 spec** — cryptographic chain-of-custody for AI workflows.

Every step in a multi-agent / multi-tool LLM workflow can emit a signed receipt that composes into a Merkle DAG. Given any output, reconstruct the full causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of [Sigstore](https://www.sigstore.dev/) for software artifacts.

- **Spec**: <https://raucle.com/spec/provenance/v1>
- **Spec version**: `raucle-provenance-receipt/v1`
- **Crypto**: Ed25519 (`crypto/ed25519`), compact JWS (RFC 7515)
- **Dependencies**: **zero** — stdlib only
- **Go version**: 1.22+
- **License**: MIT

## Install

```bash
go get github.com/craigamcw/raucle-receipt-go
```

## Quick start

```go
package main

import (
	"fmt"
	"time"

	raucle "github.com/craigamcw/raucle-receipt-go"
)

func main() {
	// 1. Generate an agent identity (do this once at deploy time)
	identity, err := raucle.GenerateIdentity(raucle.GenerateOptions{
		AgentID:       "agent:customer-support",
		AllowedModels: []string{"claude-sonnet-4-6"},
		AllowedTools:  []string{"lookup_order", "send_email"},
		TTL:           365 * 24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	// 2. Emit a root receipt when untrusted input enters the graph
	root := &raucle.Receipt{
		AgentID:    identity.AgentID,
		AgentKeyID: identity.KeyID(),
		Operation:  raucle.OpUserInput,
		InputHash:  raucle.HashText("Please send my last invoice."),
		Taint:      []string{"external_user"},
		IssuedAt:   time.Now().Unix(),
	}
	if _, err := root.Sign(identity); err != nil {
		panic(err)
	}
	fmt.Println(root.JWS)         // compact JWS string
	fmt.Println(root.ReceiptHash) // sha256:...

	// 3. Each later step cites parents
	modelCall := &raucle.Receipt{
		AgentID:    identity.AgentID,
		AgentKeyID: identity.KeyID(),
		Operation:  raucle.OpModelCall,
		Parents:    []string{root.ReceiptHash},
		Model:      "claude-sonnet-4-6",
		InputHash:  raucle.HashText("..."),
		OutputHash: raucle.HashText("..."),
		Taint:      []string{"external_user"}, // descendants carry parent taint
		IssuedAt:   time.Now().Unix(),
	}
	modelCall.Sign(identity)

	// 4. Verify chains later
	verifier, _ := raucle.NewVerifier(map[string]string{
		identity.KeyID(): identity.PublicKeyPEM(),
	})
	// ...feed in a JSONL chain via verifier.VerifyChain(io.Reader)
	_ = verifier
}
```

## What's verified

Three classes of check, all must pass for `Valid == true`:

1. **Signature**: every receipt's JWS verifies against its declared `agent_key_id`.
2. **DAG integrity**: every parent referenced by a receipt exists in the chain; receipt hashes match recomputed bytes (catches tampering).
3. **Taint monotonicity**: descendant taint ⊇ union(parent taints), unless a `sanitisation` operation explicitly lists removed tags.

## Receipt format

Compact JWS (`alg=EdDSA`, `typ=provenance-receipt/v1`). The `crit=["raucle/v1"]` header prevents JWT-compatible libraries from silently accepting receipts as bearer tokens.

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

Payload fields (canonical JSON — sorted keys, no whitespace, UTF-8):

| Field | Description |
|---|---|
| `iss`, `typ`, `iat` | Issuer, receipt-type tag, issue timestamp |
| `agent_id`, `agent_key_id` | Who emitted this step |
| `operation` | One of 8 types: `user_input`, `model_call`, `tool_call`, `retrieval`, `guardrail_scan`, `agent_handoff`, `sanitisation`, `merge` |
| `parents` | Receipt hashes of immediate predecessors (sorted) |
| `taint` | Sorted set of provenance tags for untrusted data |
| `input_hash`, `output_hash` | SHA-256 of step inputs/outputs (`sha256:` + hex). Hashes only — receipts never embed raw content. |
| `model`, `tool`, `corpus` | Operation-specific identifiers |
| `ruleset_hash`, `guardrail_verdict` | Set for `guardrail_scan` operations |
| `tenant` | Optional multi-tenant SaaS label |

A receipt's *own* hash — cited by descendants in `parents` — is `sha256:` + hex of `sha256(compact_jws_string)`. Content-addressed, deterministic.

See the full spec at <https://raucle.com/spec/provenance/v1>.

## Conformance

This module ships [the official v1 test vectors](./testdata/test-vectors.json) in its test suite. CI runs them on every PR — divergence from the spec is caught immediately.

```bash
go test ./...
```

Test output:

```
ok  github.com/craigamcw/raucle-receipt-go  0.176s
```

## Reference implementations

| Language | Repo | Status |
|---|---|---|
| Python | [craigamcw/raucle-detect](https://github.com/craigamcw/raucle-detect) | Canonical |
| TypeScript | [craigamcw/raucle-receipt-ts](https://github.com/craigamcw/raucle-receipt-ts) | v0.1.0 |
| Go | this repo | v0.1.0 |
| Rust | `craigamcw/raucle-receipt-rs` | Coming |

## Security model

Defends against tampering, forging without the agent's private key, silent taint-laundering, and unauthorised model/tool invocation.

Does NOT defend against compromised private keys, lying agents (mitigation: TEE-attested inference), or replay (mitigation: `iat` + content hashes; window enforcement is the caller's responsibility).

See [§11 Security considerations](https://raucle.com/spec/provenance/v1#11-security-considerations) in the spec for the full threat model.

## License

MIT — see [LICENSE](./LICENSE).
