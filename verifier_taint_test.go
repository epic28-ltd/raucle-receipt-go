package raucle

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newSignedIdentity builds a fresh identity, failing the test on error.
func newSignedIdentity(t *testing.T, agentID string) *AgentIdentity {
	t.Helper()
	id, err := GenerateIdentity(GenerateOptions{AgentID: agentID})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// buildLogLine signs a receipt and returns its JSONL log record string.
func buildLogLine(t *testing.T, id *AgentIdentity, r *Receipt) string {
	t.Helper()
	if _, err := r.Sign(id); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	b, err := json.Marshal(r.ToLogLine())
	if err != nil {
		t.Fatalf("marshal log line: %v", err)
	}
	return string(b)
}

// writeChainFile writes lines (joined with \n) to a temp file and returns its path.
func writeChainFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetsEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]bool
		want bool
	}{
		{"both empty", map[string]bool{}, map[string]bool{}, true},
		{"nil and empty", nil, map[string]bool{}, true},
		{"equal", map[string]bool{"x": true, "y": true}, map[string]bool{"y": true, "x": true}, true},
		{"length differs", map[string]bool{"x": true}, map[string]bool{"x": true, "y": true}, false},
		{"value differs", map[string]bool{"x": true, "y": true}, map[string]bool{"x": true, "y": false}, false},
		{"missing key", map[string]bool{"x": true, "z": true}, map[string]bool{"x": true, "y": true}, false},
	}
	for _, c := range cases {
		if got := setsEqual(c.a, c.b); got != c.want {
			t.Errorf("%s: setsEqual = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAppendErrInvalidatesReport(t *testing.T) {
	r := &VerificationReport{Valid: true}
	r.appendErr(r, "boom")
	if r.Valid {
		t.Error("Valid should be false after appendErr")
	}
	want := []string{"boom"}
	if len(r.Errors) != 1 || (len(r.Errors) == 1 && r.Errors[0] != want[0]) {
		t.Errorf("Errors = %v, want %v", r.Errors, want)
	}
}

// newVerifierFor builds a verifier trusting the identity's own key.
func newVerifierFor(t *testing.T, id *AgentIdentity) *Verifier {
	t.Helper()
	v, err := NewVerifier(map[string]string{id.KeyID(): id.PublicKeyPEM()})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyChain_LineLevelPaths(t *testing.T) {
	id := newSignedIdentity(t, "agent:chain")
	v := newVerifierFor(t, id)

	base := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpUserInput, InputHash: HashText("hi")}
	signed := buildLogLine(t, id, base)

	// Tamper the receipt_hash while keeping the valid JWS.
	var raw map[string]any
	if err := json.Unmarshal([]byte(signed), &raw); err != nil {
		t.Fatal(err)
	}
	raw["receipt_hash"] = "sha256:deadbeef"
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Re-serialise the signed JWS with no receipt_hash key at all.
	jwsOnly := map[string]any{"jws": base.JWS}
	noHash, err := json.Marshal(jwsOnly)
	if err != nil {
		t.Fatal(err)
	}

	// Unparseable JWS: three segments required.
	badJWS, err := json.Marshal(map[string]any{"jws": "not-a-jws"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		line        string
		valid       bool
		receipts    int
		sigFail     int
		errContains string
	}{
		{"valid", signed, true, 1, 0, ""},
		{"blank ignored", "", true, 0, 0, ""},
		{"invalid json", "{not json", false, 0, 0, "invalid JSON"},
		{"no jws field", `{"payload":"x"}`, false, 0, 0, "no string 'jws' field"},
		{"malformed receipt", string(badJWS), false, 0, 0, "malformed receipt"},
		{"tampered hash", string(tampered), false, 1, 0, "record tampered"},
		{"no-hash jws verifies", string(noHash), true, 1, 0, ""},
	}
	for _, c := range cases {
		report, err := v.VerifyChain(strings.NewReader(c.line + "\n"))
		if err != nil {
			t.Fatalf("%s: VerifyChain error: %v", c.name, err)
		}
		if report.Valid != c.valid {
			t.Errorf("%s: Valid = %v, want %v (errors %v)", c.name, report.Valid, c.valid, report.Errors)
		}
		if report.ReceiptCount != c.receipts {
			t.Errorf("%s: ReceiptCount = %d, want %d", c.name, report.ReceiptCount, c.receipts)
		}
		if report.SignatureFailures != c.sigFail {
			t.Errorf("%s: SignatureFailures = %d, want %d", c.name, report.SignatureFailures, c.sigFail)
		}
		if c.errContains != "" {
			found := false
			for _, e := range report.Errors {
				if strings.Contains(e, c.errContains) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no error containing %q in %v", c.name, c.errContains, report.Errors)
			}
		}
	}

	// Tampered case also records the tampered receipt hash.
	report, err := v.VerifyChain(strings.NewReader(string(tampered) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.TamperedReceipts) == 0 {
		t.Error("TamperedReceipts should be populated")
	}
}

func TestVerifyChain_ParentLinkAndTaint(t *testing.T) {
	id := newSignedIdentity(t, "agent:chain")
	v := newVerifierFor(t, id)

	parent := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpUserInput, InputHash: HashText("p"), Taint: []string{"pii"}}
	pLine := buildLogLine(t, id, parent) // signs parent first, filling ReceiptHash
	child := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpModelCall, InputHash: HashText("c"), Parents: []string{parent.ReceiptHash}, Taint: []string{}}
	// This child keeps it — must pass.
	kept := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpModelCall, InputHash: HashText("k"), Parents: []string{parent.ReceiptHash}, Taint: []string{"pii"}}
	// Orphan child references a parent outside the chain.
	orphan := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpModelCall, InputHash: HashText("o"), Parents: []string{"sha256:missing"}}

	childLine := buildLogLine(t, id, child)
	keptLine := buildLogLine(t, id, kept)
	orphanLine := buildLogLine(t, id, orphan)

	report, err := v.VerifyChain(strings.NewReader(pLine + "\n" + childLine + "\n" + keptLine + "\n" + orphanLine + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if report.ParentLinkFailures != 1 {
		t.Errorf("ParentLinkFailures = %d, want 1", report.ParentLinkFailures)
	}
	if report.TaintMonotonicityFailures != 1 {
		t.Errorf("TaintMonotonicityFailures = %d, want 1", report.TaintMonotonicityFailures)
	}
}

func TestCheckTaint_SanitisationAndUnresolvableParents(t *testing.T) {
	id := newSignedIdentity(t, "agent:chain")
	v := newVerifierFor(t, id)

	parent := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpUserInput, InputHash: HashText("p"), Taint: []string{"pii", "secret"}}
	pLine := buildLogLine(t, id, parent) // signs parent first

	// Sanitisation that removed exactly "pii": keeps "secret" only.
	sanitised := &Receipt{
		AgentID: id.AgentID, AgentKeyID: id.KeyID(),
		Operation: OpSanitisation, InputHash: HashText("s"),
		Parents: []string{parent.ReceiptHash},
		Taint:   []string{"secret"},
		Corpus:  "removed:pii",
	}
	// Sanitisation that over-removed: keeps nothing → mismatch (secret missing).
	overRemoved := &Receipt{
		AgentID: id.AgentID, AgentKeyID: id.KeyID(),
		Operation: OpSanitisation, InputHash: HashText("s2"),
		Parents: []string{parent.ReceiptHash},
		Taint:   []string{},
		Corpus:  "removed:pii",
	}
	// Parent references a hash absent from byHash: skipped, no inherited taint → matches empty set.
	sanitisedOrphan := &Receipt{
		AgentID: id.AgentID, AgentKeyID: id.KeyID(),
		Operation: OpSanitisation, InputHash: HashText("s3"),
		Parents: []string{"sha256:gone"},
	}

	lines := []string{pLine}
	for _, r := range []*Receipt{sanitised, overRemoved, sanitisedOrphan} {
		lines = append(lines, buildLogLine(t, id, r))
	}
	report, err := v.VerifyChain(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if report.TaintMonotonicityFailures != 1 {
		t.Errorf("TaintMonotonicityFailures = %d, want 1 (errors: %v)", report.TaintMonotonicityFailures, report.Errors)
	}
	found := false
	for _, e := range report.Errors {
		if strings.Contains(e, "sanitisation taint mismatch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sanitisation taint mismatch error, got %v", report.Errors)
	}

	// Empty "removed:" entries in the corpus list are ignored, not added as a tag.
	corpusOnly := &Receipt{
		AgentID: id.AgentID, AgentKeyID: id.KeyID(),
		Operation: OpSanitisation, InputHash: HashText("s4"),
		Taint:  []string{},
		Corpus: "removed:,,",
	}
	byHash := map[string]*Receipt{}
	rreport := &VerificationReport{Valid: true}
	v.checkTaint(corpusOnly, byHash, rreport)
	if !rreport.Valid {
		t.Errorf("corpus-only removal should not fail: %v", rreport.Errors)
	}
}

func TestCheckTaint_NoParentsIsNoop(t *testing.T) {
	v := &Verifier{}
	r := &Receipt{Operation: OpUserInput, Taint: []string{"x"}}
	report := &VerificationReport{Valid: true}
	v.checkTaint(r, map[string]*Receipt{}, report)
	if !report.Valid || len(report.Errors) != 0 {
		t.Errorf("expected untouched report, got %v", report.Errors)
	}
}

func TestVerifyChainFile_MissingPath(t *testing.T) {
	v := &Verifier{}
	if _, err := v.VerifyChainFile(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
		t.Fatal("expected error for missing chain file")
	}

	// Happy path: an existing chain file verifies end to end.
	id := newSignedIdentity(t, "agent:file")
	v2 := newVerifierFor(t, id)
	r := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpUserInput, InputHash: HashText("hi")}
	path := writeChainFile(t, buildLogLine(t, id, r))
	report, err := v2.VerifyChainFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || report.ReceiptCount != 1 {
		t.Errorf("Valid=%v ReceiptCount=%d errors=%v", report.Valid, report.ReceiptCount, report.Errors)
	}
}

func TestCanonical_FloatsAndStringArrays(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"integral float", float64(3), "3"},
		{"fractional float", 2.5, "2.5"},
		{"large float", 2.5e16, "2.5e+16"},
		{"string array", []string{"b", "a", "café"}, `["b","a","café"]`},
		{"int64", int64(42), "42"},
		{"uint64", uint64(7), "7"},
		{"int32", int32(-1), "-1"},
		{"int", 5, "5"},
	}
	for _, c := range cases {
		out, err := Canonicalize(c.in)
		if err != nil {
			t.Errorf("%s: Canonicalize error: %v", c.name, err)
			continue
		}
		if string(out) != c.want {
			t.Errorf("%s: got %s, want %s", c.name, out, c.want)
		}
	}
	if _, err := Canonicalize(math.NaN()); err == nil {
		t.Error("NaN should be rejected")
	}
	if _, err := Canonicalize(math.Inf(1)); err == nil {
		t.Error("Infinity should be rejected")
	}
	if _, err := Canonicalize(struct{}{}); err == nil {
		t.Error("unsupported type should be rejected")
	}
}

func TestVerifyChain_ScannerError(t *testing.T) {
	// A line longer than the token buffer makes bufio.Scanner fail.
	v := &Verifier{}
	huge := strings.Repeat("x", 17*1024*1024)
	_, err := v.VerifyChain(strings.NewReader(huge))
	if err == nil {
		t.Fatal("expected scanner error for oversized line")
	}
}

// parseRemovedTags mirrors checkSanitisationTaint's corpus parsing for tests.
func parseRemovedTags(r *Receipt) map[string]bool {
	removed := make(map[string]bool)
	if strings.HasPrefix(r.Corpus, "removed:") {
		for _, tag := range strings.Split(strings.TrimPrefix(r.Corpus, "removed:"), ",") {
			if tag != "" {
				removed[tag] = true
			}
		}
	}
	return removed
}

// receiptWithCorpus builds a minimal receipt carrying a corpus string.
func receiptWithCorpus(corpus string) *Receipt {
	return &Receipt{Operation: OpSanitisation, Corpus: corpus}
}

func TestTrace_WalksParentsBackwards(t *testing.T) {
	id := newSignedIdentity(t, "agent:trace")
	v := newVerifierFor(t, id)

	root := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpUserInput, InputHash: HashText("root")}
	rLine := buildLogLine(t, id, root) // signs root first
	mid := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpModelCall, InputHash: HashText("mid"), Parents: []string{root.ReceiptHash}}
	mLine := buildLogLine(t, id, mid) // signs mid
	leaf := &Receipt{AgentID: id.AgentID, AgentKeyID: id.KeyID(), Operation: OpToolCall, InputHash: HashText("leaf"), Parents: []string{mid.ReceiptHash}}

	path := writeChainFile(t,
		rLine,
		mLine,
		buildLogLine(t, id, leaf),
	)

	got, err := v.Trace(leaf.ReceiptHash, path)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Trace returned %d receipts, want 3 (leaf, mid, root)", len(got))
	}
	if got[0].ReceiptHash != leaf.ReceiptHash || got[2].ReceiptHash != root.ReceiptHash {
		t.Errorf("Trace order wrong: leaf→root expected, got %s→%s", got[0].ReceiptHash, got[2].ReceiptHash)
	}

	// Trace from mid hits only root and mid, and dedupes the shared parent.
	gotMid, err := v.Trace(mid.ReceiptHash, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotMid) != 2 {
		t.Errorf("Trace(mid) returned %d receipts, want 2", len(gotMid))
	}

	// Unknown hash errors out.
	if _, err := v.Trace("sha256:absent", path); err == nil {
		t.Error("expected error tracing absent receipt")
	}
}

func TestTrace_MissingFileAndB64JWSSignature(t *testing.T) {
	v := &Verifier{}
	if _, err := v.Trace("sha256:x", filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
		t.Fatal("expected error for missing chain file")
	}

	// VerifySignature with a JWS whose signature segment is not base64.
	id := newSignedIdentity(t, "agent:b64")
	r := &Receipt{JWS: "a.b.!!!", AgentKeyID: id.KeyID()}
	if v.VerifySignature(r) {
		t.Error("non-base64 signature segment should not verify")
	}
}
