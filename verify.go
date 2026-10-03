// Package verify checks Socair attestations: an in-toto Statement v1 whose
// subject is a model artifact's SHA-256 and whose predicate is a Socair report,
// in a DSSE envelope signed with Ed25519.
//
// It is the small, dependency-free half of Socair that a consumer such as an
// admission controller needs: it verifies an attestation and applies an
// admission policy, and nothing else. It never scans an artifact. Producing
// attestations is Socair's job.
//
// A verified attestation says that a trusted key vouched for the report about
// that exact artifact hash. It never certifies more than the report's own
// bounded statement.
package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const (
	// StatementType is the in-toto Statement v1 type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType names the Socair report predicate.
	PredicateType = "https://socair.ai/attestation/v1"
	// PayloadType is the DSSE payload type for an in-toto statement.
	PayloadType = "application/vnd.in-toto+json"
	// SchemaVersion is the report contract this package reads.
	SchemaVersion = "socair.report/v1"
)

// Promotion states a report can carry.
const (
	StateAuthorized               = "authorized"
	StateAuthorizedWithConditions = "authorized_with_conditions"
	StateWithheld                 = "withheld"
	StateEscalated                = "escalated"
)

// ErrVerify marks an attestation that does not verify. The reason is in the
// error.
var ErrVerify = errors.New("attestation does not verify")

func verifyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Check is one row of the report.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// predicate is the part of the Socair report this package reads.
type predicate struct {
	SchemaVersion string `json:"schema_version"`
	Header        struct {
		DocumentID string `json:"document_id"`
		IssuedUTC  string `json:"issued_utc"`
	} `json:"header"`
	Artifact struct {
		FileName string `json:"file_name"`
		SHA256   string `json:"sha256"`
	} `json:"artifact"`
	Checks                 []Check `json:"checks"`
	PromotionAuthorization struct {
		State            string   `json:"state"`
		Authorized       bool     `json:"authorized"`
		AcceptedBy       string   `json:"accepted_by"`
		AcceptedSurfaces []string `json:"accepted_surfaces"`
	} `json:"promotion_authorization"`
	Verification struct {
		DocumentHash string `json:"document_hash"`
		SignerKeyID  string `json:"signer_key_id"`
	} `json:"verification"`
}

// Attestation is a verified attestation.
type Attestation struct {
	// SHA256 is the attested artifact's digest, lowercase hex.
	SHA256   string
	FileName string
	// KeyID identifies the trusted key that signed it.
	KeyID      string
	DocumentID string
	IssuedUTC  string
	// State is the report's promotion state.
	State            string
	AcceptedBy       string
	AcceptedSurfaces []string
	Checks           []Check
	DocumentHash     string
	// Predicate is the full report, for a caller that needs more of it.
	Predicate json.RawMessage
}

// pae is DSSE's pre-authentication encoding, the bytes actually signed.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Verify checks an envelope against trusted keys and returns the attestation
// it carries. In order: a signature by a key in ring over the DSSE encoding;
// the statement and predicate types and the report schema; that the subject
// digest is the report's artifact hash; that the report names the key that
// signed it; and that the promotion state follows from the checks, so even a
// trusted signer cannot attest a state its own report does not support.
func Verify(env []byte, ring Keyring) (*Attestation, error) {
	var e envelope
	if err := json.Unmarshal(env, &e); err != nil {
		return nil, verifyErr("not a DSSE envelope: %v", err)
	}
	if e.PayloadType != PayloadType {
		return nil, verifyErr("payload type %q, want %q", e.PayloadType, PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, verifyErr("payload is not base64: %v", err)
	}
	if len(e.Signatures) == 0 {
		return nil, verifyErr("envelope is unsigned")
	}
	if len(ring) == 0 {
		return nil, verifyErr("no trusted keys configured")
	}

	signedBy := ""
	msg := pae(e.PayloadType, payload)
	for _, s := range e.Signatures {
		pub, ok := ring[s.KeyID]
		if !ok {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			signedBy = s.KeyID
			break
		}
	}
	if signedBy == "" {
		ids := make([]string, 0, len(e.Signatures))
		for _, s := range e.Signatures {
			ids = append(ids, s.KeyID)
		}
		return nil, verifyErr("no valid signature by a trusted key (signed by %v; %d key(s) trusted)", ids, len(ring))
	}

	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, verifyErr("payload is not an in-toto statement: %v", err)
	}
	if st.Type != StatementType {
		return nil, verifyErr("statement type %q, want %q", st.Type, StatementType)
	}
	if st.PredicateType != PredicateType {
		return nil, verifyErr("predicate type %q, want %q", st.PredicateType, PredicateType)
	}
	if len(st.Subject) != 1 {
		return nil, verifyErr("statement has %d subjects, want 1", len(st.Subject))
	}
	var p predicate
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, verifyErr("predicate is not a Socair report: %v", err)
	}
	if p.SchemaVersion != SchemaVersion {
		return nil, verifyErr("report schema %q, want %q", p.SchemaVersion, SchemaVersion)
	}
	sha := st.Subject[0].Digest["sha256"]
	if !isHex64(sha) || sha != p.Artifact.SHA256 {
		return nil, verifyErr("subject digest %q is not the report's artifact hash %q", sha, p.Artifact.SHA256)
	}
	if p.Verification.SignerKeyID != signedBy {
		return nil, verifyErr("report names signer %q but was signed by %q", p.Verification.SignerKeyID, signedBy)
	}
	if err := stateFollowsFromChecks(p); err != nil {
		return nil, verifyErr("%v", err)
	}
	return &Attestation{
		SHA256:           sha,
		FileName:         p.Artifact.FileName,
		KeyID:            signedBy,
		DocumentID:       p.Header.DocumentID,
		IssuedUTC:        p.Header.IssuedUTC,
		State:            p.PromotionAuthorization.State,
		AcceptedBy:       p.PromotionAuthorization.AcceptedBy,
		AcceptedSurfaces: p.PromotionAuthorization.AcceptedSurfaces,
		Checks:           p.Checks,
		DocumentHash:     p.Verification.DocumentHash,
		Predicate:        st.Predicate,
	}, nil
}

// stateFollowsFromChecks mirrors Socair's own rule: authorized needs every
// check PASS; authorized_with_conditions needs no FAIL or LEAD and every
// NOT_TESTED check accepted by a named person; the authorized flag agrees.
func stateFollowsFromChecks(p predicate) error {
	pa := p.PromotionAuthorization
	switch pa.State {
	case StateAuthorized, StateAuthorizedWithConditions, StateWithheld, StateEscalated:
	default:
		return fmt.Errorf("unknown promotion state %q", pa.State)
	}
	want := pa.State == StateAuthorized || pa.State == StateAuthorizedWithConditions
	if pa.Authorized != want {
		return fmt.Errorf("authorized flag %v disagrees with state %q", pa.Authorized, pa.State)
	}
	if !want {
		return nil
	}
	if len(p.Checks) == 0 {
		return fmt.Errorf("state %q with no checks", pa.State)
	}
	accepted := map[string]bool{}
	for _, s := range pa.AcceptedSurfaces {
		accepted[s] = true
	}
	if pa.State == StateAuthorizedWithConditions && pa.AcceptedBy == "" {
		return errors.New("authorized_with_conditions names no acceptor")
	}
	for _, c := range p.Checks {
		switch c.Status {
		case "PASS":
		case "FAIL", "LEAD":
			return fmt.Errorf("state %q over %s check %q", pa.State, c.Status, c.Name)
		case "NOT_TESTED":
			if pa.State == StateAuthorized || !accepted[c.Name] {
				return fmt.Errorf("state %q over unaccepted NOT_TESTED check %q", pa.State, c.Name)
			}
		default:
			return fmt.Errorf("check %q has unknown status %q", c.Name, c.Status)
		}
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
