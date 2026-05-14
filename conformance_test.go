package raucle

import (
	"encoding/json"
	"os"
	"testing"
)

type testVector struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	ExpectedJWS         string `json:"expected_jws"`
	ExpectedReceiptHash string `json:"expected_receipt_hash"`
}

type vectorFile struct {
	SpecVersion      string       `json:"spec_version"`
	GeneratorVersion string       `json:"generator_version"`
	AgentID          string       `json:"agent_id"`
	AgentKeyID       string       `json:"agent_key_id"`
	PublicKeyPEM     string       `json:"public_key_pem"`
	Vectors          []testVector `json:"vectors"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/test-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

// TestSpec_VectorFileWellFormed sanity-checks the file before the more
// specific tests below.
func TestSpec_VectorFileWellFormed(t *testing.T) {
	v := loadVectors(t)
	if v.SpecVersion != "raucle-provenance-receipt/v1" {
		t.Fatalf("spec_version = %q, want raucle-provenance-receipt/v1", v.SpecVersion)
	}
	if len(v.Vectors) < 5 {
		t.Fatalf("got %d vectors, want at least 5", len(v.Vectors))
	}
}

// TestSpec_ReceiptHashRecomputesByteForByte: the most important conformance
// check. If this fails, our canonicalisation / JWS construction / hashing has
// drifted from the spec.
func TestSpec_ReceiptHashRecomputesByteForByte(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			r, err := FromJWS(vec.ExpectedJWS)
			if err != nil {
				t.Fatalf("FromJWS: %v", err)
			}
			if r.ReceiptHash != vec.ExpectedReceiptHash {
				t.Fatalf("receipt_hash = %s, want %s", r.ReceiptHash, vec.ExpectedReceiptHash)
			}
		})
	}
}

// TestSpec_SignaturesVerifyAgainstPublishedKey: every vector's signature
// MUST verify against the public key shipped in the vector file. If this
// fails our Ed25519 use is wrong.
func TestSpec_SignaturesVerifyAgainstPublishedKey(t *testing.T) {
	v := loadVectors(t)
	verifier, err := NewVerifier(map[string]string{v.AgentKeyID: v.PublicKeyPEM})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	for _, vec := range v.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			r, err := FromJWS(vec.ExpectedJWS)
			if err != nil {
				t.Fatalf("FromJWS: %v", err)
			}
			if !verifier.VerifySignature(r) {
				t.Fatalf("signature did not verify against published pubkey")
			}
		})
	}
}

// TestSpec_VectorsCoverRequiredOperations: the published vectors MUST
// exercise the most-bug-prone operation types.
func TestSpec_VectorsCoverRequiredOperations(t *testing.T) {
	v := loadVectors(t)
	seen := make(map[Operation]bool)
	for _, vec := range v.Vectors {
		r, err := FromJWS(vec.ExpectedJWS)
		if err != nil {
			t.Fatalf("FromJWS: %v", err)
		}
		seen[r.Operation] = true
	}
	for _, op := range []Operation{OpUserInput, OpModelCall, OpToolCall, OpSanitisation, OpGuardrailScan} {
		if !seen[op] {
			t.Errorf("vectors missing operation %q", op)
		}
	}
}
