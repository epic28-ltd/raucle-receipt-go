package raucle

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerificationReport describes the outcome of verifying a chain.
type VerificationReport struct {
	Valid                     bool
	ReceiptCount              int
	SignatureFailures         int
	ParentLinkFailures        int
	TaintMonotonicityFailures int
	TamperedReceipts          []string
	Errors                    []string
}

// Verifier verifies provenance chains against a set of public keys.
type Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewVerifier constructs a Verifier from key_id → PEM mappings.
func NewVerifier(publicKeysPEM map[string]string) (*Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(publicKeysPEM))
	for kid, pem := range publicKeysPEM {
		pub, err := LoadPublicKey(pem)
		if err != nil {
			return nil, fmt.Errorf("load key %s: %w", kid, err)
		}
		keys[kid] = pub
	}
	return &Verifier{keys: keys}, nil
}

// VerifyChainFile reads a JSONL chain file and verifies it.
func (v *Verifier) VerifyChainFile(path string) (*VerificationReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return v.VerifyChain(f)
}

// VerifyChain reads JSONL lines from r and verifies the chain.
func (v *Verifier) VerifyChain(r io.Reader) (*VerificationReport, error) {
	report := &VerificationReport{Valid: true}
	byHash := make(map[string]*Receipt)
	storedHash := make(map[string]string)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // allow large lines
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		v.processChainLine(report, byHash, storedHash, strings.TrimSpace(scanner.Text()), lineNo)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// DAG integrity + taint monotonicity
	for _, receipt := range byHash {
		for _, parent := range receipt.Parents {
			if _, ok := byHash[parent]; !ok {
				report.ParentLinkFailures++
				report.appendErr(report, fmt.Sprintf("receipt %s: parent %s not in chain", receipt.ReceiptHash, parent))
			}
		}
		v.checkTaint(receipt, byHash, report)
	}

	return report, nil
}

// processChainLine decodes one JSONL record and updates the report and the
// by-hash / stored-hash indexes. Blank lines are ignored.
func (v *Verifier) processChainLine(report *VerificationReport, byHash map[string]*Receipt, storedHash map[string]string, line string, lineNo int) {
	if line == "" {
		return
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		report.appendErr(report, fmt.Sprintf("line %d: invalid JSON: %v", lineNo, err))
		return
	}
	jws, ok := raw["jws"].(string)
	if !ok {
		report.appendErr(report, fmt.Sprintf("line %d: record has no string 'jws' field", lineNo))
		return
	}
	receipt, err := FromJWS(jws)
	if err != nil {
		report.appendErr(report, fmt.Sprintf("line %d: malformed receipt: %v", lineNo, err))
		return
	}
	// Tampering check
	if stored, ok := raw["receipt_hash"].(string); ok {
		if stored != receipt.ReceiptHash {
			report.TamperedReceipts = append(report.TamperedReceipts, receipt.ReceiptHash)
			report.appendErr(report, fmt.Sprintf("line %d: receipt_hash mismatch — record tampered", lineNo))
		}
		storedHash[jws] = stored
	}
	// Signature
	if !v.VerifySignature(receipt) {
		report.SignatureFailures++
		report.appendErr(report, fmt.Sprintf("line %d: signature verification failed for agent_key_id=%s", lineNo, receipt.AgentKeyID))
	}

	byHash[receipt.ReceiptHash] = receipt
	report.ReceiptCount++
}

// VerifySignature checks the Ed25519 signature on a receipt against the
// configured public keys.
func (v *Verifier) VerifySignature(receipt *Receipt) bool {
	key, ok := v.keys[receipt.AgentKeyID]
	if !ok {
		return false
	}
	parts := strings.Split(receipt.JWS, ".")
	if len(parts) != 3 {
		return false
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := B64URLDecode(parts[2])
	if err != nil {
		return false
	}
	return ed25519.Verify(key, signingInput, sig)
}

// Trace walks the DAG backwards from leaf to all roots, deduplicated, BFS order.
func (v *Verifier) Trace(receiptHash, chainPath string) ([]*Receipt, error) {
	f, err := os.Open(chainPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	all := make(map[string]*Receipt)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		jws, _ := raw["jws"].(string)
		if jws == "" {
			continue
		}
		r, err := FromJWS(jws)
		if err != nil {
			continue
		}
		all[r.ReceiptHash] = r
	}
	if _, ok := all[receiptHash]; !ok {
		return nil, fmt.Errorf("receipt %s not found in chain", receiptHash)
	}
	var out []*Receipt
	visited := make(map[string]bool)
	queue := []string{receiptHash}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true
		r, ok := all[current]
		if !ok {
			continue
		}
		out = append(out, r)
		queue = append(queue, r.Parents...)
	}
	return out, nil
}

func (v *Verifier) checkTaint(receipt *Receipt, byHash map[string]*Receipt, report *VerificationReport) {
	if len(receipt.Parents) == 0 {
		return
	}
	inherited := collectInheritedTaint(receipt.Parents, byHash)
	mine := make(map[string]bool)
	for _, t := range receipt.Taint {
		mine[t] = true
	}
	if receipt.Operation == OpSanitisation {
		checkSanitisationTaint(receipt, inherited, mine, report)
	} else {
		checkMonotonicTaint(receipt, inherited, mine, report)
	}
}

// collectInheritedTaint unions the taint tags of all resolvable parents.
func collectInheritedTaint(parents []string, byHash map[string]*Receipt) map[string]bool {
	inherited := make(map[string]bool)
	for _, p := range parents {
		parent, ok := byHash[p]
		if !ok {
			continue
		}
		for _, t := range parent.Taint {
			inherited[t] = true
		}
	}
	return inherited
}

// checkSanitisationTaint enforces that a sanitisation receipt carries exactly
// the inherited taint minus the tags removed via "removed:" corpus entries.
func checkSanitisationTaint(receipt *Receipt, inherited map[string]bool, mine map[string]bool, report *VerificationReport) {
	removed := make(map[string]bool)
	if strings.HasPrefix(receipt.Corpus, "removed:") {
		for _, tag := range strings.Split(strings.TrimPrefix(receipt.Corpus, "removed:"), ",") {
			if tag != "" {
				removed[tag] = true
			}
		}
	}
	expected := make(map[string]bool)
	for t := range inherited {
		if !removed[t] {
			expected[t] = true
		}
	}
	if !setsEqual(expected, mine) {
		report.TaintMonotonicityFailures++
		report.appendErr(report, fmt.Sprintf("receipt %s: sanitisation taint mismatch", receipt.ReceiptHash))
	}
}

// checkMonotonicTaint enforces that non-sanitisation operations keep every
// inherited taint tag.
func checkMonotonicTaint(receipt *Receipt, inherited map[string]bool, mine map[string]bool, report *VerificationReport) {
	var missing []string
	for t := range inherited {
		if !mine[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		report.TaintMonotonicityFailures++
		report.appendErr(report, fmt.Sprintf("receipt %s: taint not monotonic — dropped %v without a sanitisation step", receipt.ReceiptHash, missing))
	}
}

func (r *VerificationReport) appendErr(_ *VerificationReport, msg string) {
	r.Errors = append(r.Errors, msg)
	r.Valid = false
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
