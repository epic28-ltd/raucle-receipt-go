package raucle

import (
	"strings"
	"testing"
	"time"
)

func TestCanonical_SortsKeysAndOmitsWhitespace(t *testing.T) {
	out, err := Canonicalize(map[string]any{"b": 1, "a": 2})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(out) != `{"a":2,"b":1}` {
		t.Fatalf("got %q, want {\"a\":2,\"b\":1}", out)
	}
}

func TestCanonical_NestedDeepKeysSort(t *testing.T) {
	out, _ := Canonicalize(map[string]any{
		"z": 1,
		"a": map[string]any{"b": 2, "a": 1},
	})
	if string(out) != `{"a":{"a":1,"b":2},"z":1}` {
		t.Fatalf("got %q", out)
	}
}

func TestCanonical_NonASCIIPassesThrough(t *testing.T) {
	out, _ := Canonicalize("café")
	if string(out) != `"café"` {
		t.Fatalf("got %q, want \"café\"", out)
	}
	out2, _ := Canonicalize("→")
	if string(out2) != `"→"` {
		t.Fatalf("got %q, want \"→\"", out2)
	}
}

func TestCanonical_EscapesJSONControlChars(t *testing.T) {
	out, _ := Canonicalize("a\nb")
	if string(out) != `"a\nb"` {
		t.Fatalf("got %q", out)
	}
	out2, _ := Canonicalize(`he said "hi"`)
	if string(out2) != `"he said \"hi\""` {
		t.Fatalf("got %q", out2)
	}
}

func TestHash_DeterministicAndPrefixed(t *testing.T) {
	a := HashText("hello")
	if a != HashText("hello") {
		t.Fatal("HashText is not deterministic")
	}
	if a == HashText("world") {
		t.Fatal("different inputs hashed to same value")
	}
	if !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("missing sha256: prefix in %q", a)
	}
	if len(a) != len("sha256:")+64 {
		t.Fatalf("hash length %d, want %d", len(a), len("sha256:")+64)
	}
}

func TestHash_ObjOrderIndependent(t *testing.T) {
	a := MustHashObj(map[string]any{"a": 1, "b": 2})
	b := MustHashObj(map[string]any{"b": 2, "a": 1})
	if a != b {
		t.Fatalf("hash differs by key order: %s vs %s", a, b)
	}
}

func TestIdentity_ValidatesAgentID(t *testing.T) {
	cases := []struct {
		id    string
		valid bool
	}{
		{"agent:ok", true},
		{"agent:my.service-v1", true},
		{"no-prefix", false},
		{"AGENT:upper", false},
		{"agent:Has Space", false},
		{"agent:", false},
	}
	for _, c := range cases {
		err := ValidateAgentID(c.id)
		if (err == nil) != c.valid {
			t.Errorf("ValidateAgentID(%q) valid=%v, want %v", c.id, err == nil, c.valid)
		}
	}
}

func TestIdentity_GenerateSelfSignsStatement(t *testing.T) {
	id, err := GenerateIdentity(GenerateOptions{
		AgentID:       "agent:x",
		AllowedModels: []string{"claude-sonnet-4-6"},
		AllowedTools:  []string{"send_email"},
	})
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if len(id.KeyID()) != 16 {
		t.Fatalf("KeyID length %d, want 16", len(id.KeyID()))
	}
	if id.Statement.Signature == "" {
		t.Fatal("statement signature is empty")
	}
	if !id.Statement.PermitsModel("claude-sonnet-4-6") {
		t.Fatal("should permit listed model")
	}
	if id.Statement.PermitsModel("rogue-model") {
		t.Fatal("should NOT permit unlisted model")
	}
	if id.Statement.PermitsTool("send_email") != true {
		t.Fatal("should permit listed tool")
	}
	if id.Statement.PermitsTool("delete_db") != false {
		t.Fatal("should NOT permit unlisted tool")
	}
}

func TestIdentity_DefaultAllowlistsUnrestricted(t *testing.T) {
	id, err := GenerateIdentity(GenerateOptions{AgentID: "agent:x"})
	if err != nil {
		t.Fatal(err)
	}
	if !id.Statement.PermitsModel("anything") {
		t.Fatal("empty allowed_models should be unrestricted")
	}
	if !id.Statement.PermitsTool("anything") {
		t.Fatal("empty allowed_tools should be unrestricted")
	}
}

func TestReceipt_RoundTripVerifies(t *testing.T) {
	id, err := GenerateIdentity(GenerateOptions{AgentID: "agent:rt", TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r := &Receipt{
		AgentID:    id.AgentID,
		AgentKeyID: id.KeyID(),
		Operation:  OpUserInput,
		InputHash:  HashText("hello"),
		Taint:      []string{"external_user"},
		IssuedAt:   1700000000,
	}
	if _, err := r.Sign(id); err != nil {
		t.Fatal(err)
	}
	if strings.Count(r.JWS, ".") != 2 {
		t.Fatalf("JWS has %d dots, want 2", strings.Count(r.JWS, "."))
	}
	if !strings.HasPrefix(r.ReceiptHash, "sha256:") {
		t.Fatalf("ReceiptHash %q missing prefix", r.ReceiptHash)
	}
	v, err := NewVerifier(map[string]string{id.KeyID(): id.PublicKeyPEM()})
	if err != nil {
		t.Fatal(err)
	}
	if !v.VerifySignature(r) {
		t.Fatal("signature did not verify against own key")
	}
}

func TestReceipt_TamperedJWSFailsVerification(t *testing.T) {
	id, err := GenerateIdentity(GenerateOptions{AgentID: "agent:tamper"})
	if err != nil {
		t.Fatal(err)
	}
	r := &Receipt{
		AgentID:    id.AgentID,
		AgentKeyID: id.KeyID(),
		Operation:  OpUserInput,
		InputHash:  HashText("hi"),
		IssuedAt:   1700000000,
	}
	if _, err := r.Sign(id); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(r.JWS, ".")
	// Flip last char of payload segment
	if last := parts[1][len(parts[1])-1]; last == 'A' {
		parts[1] = parts[1][:len(parts[1])-1] + "B"
	} else {
		parts[1] = parts[1][:len(parts[1])-1] + "A"
	}
	tampered := &Receipt{JWS: strings.Join(parts, "."), AgentKeyID: id.KeyID()}
	v, _ := NewVerifier(map[string]string{id.KeyID(): id.PublicKeyPEM()})
	if v.VerifySignature(tampered) {
		t.Fatal("tampered JWS should not verify")
	}
}
