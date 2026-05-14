package raucle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// agentIDRE encodes the Raucle spec §5 agent_id validation rule.
var agentIDRE = regexp.MustCompile(`^agent:[a-z0-9][a-z0-9_\-./]{0,127}$`)

// ValidateAgentID returns nil if id is a valid agent identifier per the spec.
func ValidateAgentID(id string) error {
	if !agentIDRE.MatchString(id) {
		return fmt.Errorf(
			"agent_id %q must match %s (lowercase, alphanumeric + _-./, 1-128 chars, prefix 'agent:')",
			id, agentIDRE.String(),
		)
	}
	return nil
}

// CapabilityStatement is the signed declaration of what an agent is
// permitted to do. Distributed alongside the agent's public key.
type CapabilityStatement struct {
	AgentID             string   `json:"agent_id"`
	KeyID               string   `json:"key_id"`
	PublicKeyPEM        string   `json:"public_key_pem"`
	AllowedModels       []string `json:"allowed_models"`
	AllowedTools        []string `json:"allowed_tools"`
	DataClassifications []string `json:"data_classifications"`
	Issuer              string   `json:"issuer"`
	IssuedAt            int64    `json:"issued_at"`
	ExpiresAt           *int64   `json:"expires_at"`
	Signature           string   `json:"signature"`
}

// Body returns the canonical signed-body fields (excluding signature).
// The returned map is what gets canonicalised + Ed25519-signed.
func (c *CapabilityStatement) Body() map[string]any {
	allowed := func(s []string) []any {
		out := make([]any, len(s))
		copyAndSort := slices.Clone(s)
		slices.Sort(copyAndSort)
		for i, v := range copyAndSort {
			out[i] = v
		}
		return out
	}
	var expires any
	if c.ExpiresAt != nil {
		expires = *c.ExpiresAt
	} else {
		expires = nil
	}
	return map[string]any{
		"agent_id":             c.AgentID,
		"key_id":               c.KeyID,
		"public_key_pem":       c.PublicKeyPEM,
		"allowed_models":       allowed(c.AllowedModels),
		"allowed_tools":        allowed(c.AllowedTools),
		"data_classifications": allowed(c.DataClassifications),
		"issuer":               c.Issuer,
		"issued_at":            c.IssuedAt,
		"expires_at":           expires,
	}
}

// PermitsModel returns true if the agent may call the named model.
// An empty AllowedModels list means unrestricted.
func (c *CapabilityStatement) PermitsModel(model string) bool {
	return len(c.AllowedModels) == 0 || slices.Contains(c.AllowedModels, model)
}

// PermitsTool returns true if the agent may call the named tool.
// An empty AllowedTools list means unrestricted.
func (c *CapabilityStatement) PermitsTool(tool string) bool {
	return len(c.AllowedTools) == 0 || slices.Contains(c.AllowedTools, tool)
}

// AgentIdentity wraps an Ed25519 private key + signed capability statement.
// Acts as the agent's "TLS certificate".
type AgentIdentity struct {
	AgentID    string
	PrivateKey ed25519.PrivateKey
	Statement  *CapabilityStatement
}

// KeyID returns the agent_key_id (16 lowercase hex of sha256(public_key_pem)).
func (a *AgentIdentity) KeyID() string { return a.Statement.KeyID }

// PublicKeyPEM returns the PEM-encoded public key.
func (a *AgentIdentity) PublicKeyPEM() string { return a.Statement.PublicKeyPEM }

// PrivateKeyPEM returns the PEM-encoded private key (PKCS8, no encryption).
func (a *AgentIdentity) PrivateKeyPEM() (string, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(a.PrivateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), nil
}

// Sign signs data with the agent's Ed25519 private key.
func (a *AgentIdentity) Sign(data []byte) []byte {
	return ed25519.Sign(a.PrivateKey, data)
}

// GenerateOptions configures GenerateIdentity.
type GenerateOptions struct {
	AgentID             string
	AllowedModels       []string
	AllowedTools        []string
	DataClassifications []string
	Issuer              string
	TTL                 time.Duration
}

// GenerateIdentity generates a fresh Ed25519 keypair and self-signed
// capability statement.
func GenerateIdentity(opts GenerateOptions) (*AgentIdentity, error) {
	if err := ValidateAgentID(opts.AgentID); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return identityFromKey(priv, pub, opts)
}

// LoadIdentity rebuilds an AgentIdentity from a stored private-key PEM and
// capability statement.
func LoadIdentity(privateKeyPEM string, stmt *CapabilityStatement) (*AgentIdentity, error) {
	if err := ValidateAgentID(stmt.AgentID); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 private key: %T", key)
	}
	return &AgentIdentity{
		AgentID:    stmt.AgentID,
		PrivateKey: priv,
		Statement:  stmt,
	}, nil
}

// LoadPublicKey parses a PEM-encoded Ed25519 public key.
func LoadPublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 public key: %T", key)
	}
	return pub, nil
}

// identityFromKey is shared by GenerateIdentity and the deterministic
// test-vector helpers.
func identityFromKey(priv ed25519.PrivateKey, pub ed25519.PublicKey, opts GenerateOptions) (*AgentIdentity, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))
	keyID := SHA256Hex([]byte(pubPEM))[:16]
	issuer := opts.Issuer
	if issuer == "" {
		issuer = "raucle-detect"
	}
	now := time.Now().Unix()
	var expires *int64
	if opts.TTL > 0 {
		exp := now + int64(opts.TTL.Seconds())
		expires = &exp
	}
	stmt := &CapabilityStatement{
		AgentID:             opts.AgentID,
		KeyID:               keyID,
		PublicKeyPEM:        pubPEM,
		AllowedModels:       append([]string{}, opts.AllowedModels...),
		AllowedTools:        append([]string{}, opts.AllowedTools...),
		DataClassifications: append([]string{}, opts.DataClassifications...),
		Issuer:              issuer,
		IssuedAt:            now,
		ExpiresAt:           expires,
	}
	bodyBytes, err := Canonicalize(stmt.Body())
	if err != nil {
		return nil, err
	}
	stmt.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bodyBytes))
	return &AgentIdentity{
		AgentID:    opts.AgentID,
		PrivateKey: priv,
		Statement:  stmt,
	}, nil
}
