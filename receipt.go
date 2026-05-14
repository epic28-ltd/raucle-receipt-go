package raucle

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Operation is one of the eight Raucle v1 operation types.
type Operation string

const (
	OpUserInput     Operation = "user_input"
	OpModelCall     Operation = "model_call"
	OpToolCall      Operation = "tool_call"
	OpRetrieval     Operation = "retrieval"
	OpGuardrailScan Operation = "guardrail_scan"
	OpAgentHandoff  Operation = "agent_handoff"
	OpSanitisation  Operation = "sanitisation"
	OpMerge         Operation = "merge"
)

// AllOperations is the set of valid operation tags per spec §6.
var AllOperations = []Operation{
	OpUserInput,
	OpModelCall,
	OpToolCall,
	OpRetrieval,
	OpGuardrailScan,
	OpAgentHandoff,
	OpSanitisation,
	OpMerge,
}

// ReceiptTyp is the JOSE/payload typ value for v1 receipts.
const ReceiptTyp = "provenance-receipt/v1"

// RaucleVersionTag is the value that MUST appear in the JWS crit array.
const RaucleVersionTag = "raucle/v1"

// Issuer is the iss value emitted by this implementation.
const Issuer = "raucle-detect/provenance"

// Receipt is a single Raucle Provenance Receipt v1.
type Receipt struct {
	AgentID          string
	AgentKeyID       string
	Operation        Operation
	Parents          []string
	InputHash        string
	OutputHash       string
	Model            string
	Tool             string
	Corpus           string
	RulesetHash      string
	GuardrailVerdict string
	Taint            []string
	Tenant           *string
	IssuedAt         int64

	// Populated after Sign or FromJWS.
	JWS         string
	ReceiptHash string
}

// Payload returns the canonical signed-payload map per spec §4.2.
func (r *Receipt) Payload() map[string]any {
	parents := slices.Clone(r.Parents)
	slices.Sort(parents)
	taint := slices.Clone(r.Taint)
	slices.Sort(taint)
	parentsAny := make([]any, len(parents))
	for i, p := range parents {
		parentsAny[i] = p
	}
	taintAny := make([]any, len(taint))
	for i, t := range taint {
		taintAny[i] = t
	}
	out := map[string]any{
		"iss":          Issuer,
		"typ":          ReceiptTyp,
		"iat":          r.IssuedAt,
		"agent_id":     r.AgentID,
		"agent_key_id": r.AgentKeyID,
		"operation":    string(r.Operation),
		"parents":      parentsAny,
		"taint":        taintAny,
	}
	if r.InputHash != "" {
		out["input_hash"] = r.InputHash
	}
	if r.OutputHash != "" {
		out["output_hash"] = r.OutputHash
	}
	if r.Model != "" {
		out["model"] = r.Model
	}
	if r.Tool != "" {
		out["tool"] = r.Tool
	}
	if r.Corpus != "" {
		out["corpus"] = r.Corpus
	}
	if r.RulesetHash != "" {
		out["ruleset_hash"] = r.RulesetHash
	}
	if r.GuardrailVerdict != "" {
		out["guardrail_verdict"] = r.GuardrailVerdict
	}
	if r.Tenant != nil {
		out["tenant"] = *r.Tenant
	}
	return out
}

// Sign signs the receipt with identity and populates JWS + ReceiptHash.
// Returns the compact JWS string.
func (r *Receipt) Sign(identity *AgentIdentity) (string, error) {
	header := map[string]any{
		"alg":            "EdDSA",
		"typ":            ReceiptTyp,
		"kid":            identity.KeyID(),
		"crit":           []any{RaucleVersionTag},
		RaucleVersionTag: "provenance",
	}
	headerBytes, err := Canonicalize(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := Canonicalize(r.Payload())
	if err != nil {
		return "", err
	}
	headerB64 := B64URLEncode(headerBytes)
	payloadB64 := B64URLEncode(payloadBytes)
	signingInput := []byte(headerB64 + "." + payloadB64)
	sig := identity.Sign(signingInput)
	r.JWS = headerB64 + "." + payloadB64 + "." + B64URLEncode(sig)
	r.ReceiptHash = "sha256:" + SHA256Hex([]byte(r.JWS))
	return r.JWS, nil
}

// FromJWS parses a compact JWS string back into a Receipt. Does NOT verify
// the signature — use Verifier.VerifySignature for that.
func FromJWS(jws string) (*Receipt, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWS — expected three dot-separated segments")
	}
	payloadBytes, err := B64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var p map[string]any
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	op := Operation(asString(p["operation"]))
	if !slices.Contains(AllOperations, op) {
		return nil, fmt.Errorf("unknown operation %q", op)
	}
	r := &Receipt{
		AgentID:          asString(p["agent_id"]),
		AgentKeyID:       asString(p["agent_key_id"]),
		Operation:        op,
		Parents:          asStringSlice(p["parents"]),
		InputHash:        asString(p["input_hash"]),
		OutputHash:       asString(p["output_hash"]),
		Model:            asString(p["model"]),
		Tool:             asString(p["tool"]),
		Corpus:           asString(p["corpus"]),
		RulesetHash:      asString(p["ruleset_hash"]),
		GuardrailVerdict: asString(p["guardrail_verdict"]),
		Taint:            asStringSlice(p["taint"]),
		IssuedAt:         asInt64(p["iat"]),
	}
	if t, ok := p["tenant"].(string); ok {
		r.Tenant = &t
	}
	r.JWS = jws
	r.ReceiptHash = "sha256:" + SHA256Hex([]byte(jws))
	return r, nil
}

// ToLogLine produces the JSONL on-disk record: payload + receipt_hash + jws.
// The returned map is safe to marshal with encoding/json (key order doesn't
// matter on the JSONL record — only the inner JWS is signed).
func (r *Receipt) ToLogLine() map[string]any {
	out := r.Payload()
	out["receipt_hash"] = r.ReceiptHash
	out["jws"] = r.JWS
	return out
}

// Helpers for the loose JSON decoded values.

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	default:
		return 0
	}
}
