// Package raucle is the Go reference implementation of the Raucle
// Provenance Receipt v1 specification.
//
// Cryptographic chain-of-custody for AI workflows. Every step in a
// multi-agent / multi-tool LLM workflow can emit a signed receipt that
// composes into a Merkle DAG. Given any output, you can reconstruct the
// entire causal chain back to the original input and prove nothing in
// the chain has been tampered with.
//
// Spec: https://raucle.com/spec/provenance/v1
//
// Zero runtime dependencies — uses Go's standard library only
// (crypto/ed25519, crypto/sha256, crypto/x509, encoding/pem, encoding/json).
//
// Quick start:
//
//	identity, err := raucle.GenerateIdentity(raucle.GenerateOptions{
//	    AgentID:       "agent:customer-support",
//	    AllowedModels: []string{"claude-sonnet-4-6"},
//	})
//	if err != nil { return err }
//
//	root := &raucle.Receipt{
//	    AgentID:    identity.AgentID,
//	    AgentKeyID: identity.KeyID(),
//	    Operation:  raucle.OpUserInput,
//	    InputHash:  raucle.HashText("Hello"),
//	    Taint:      []string{"external_user"},
//	    IssuedAt:   time.Now().Unix(),
//	}
//	if err := root.Sign(identity); err != nil { return err }
//	fmt.Println(root.JWS)         // compact JWS string
//	fmt.Println(root.ReceiptHash) // sha256:...
package raucle
