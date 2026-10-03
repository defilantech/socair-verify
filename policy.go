package verify

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrPolicy marks an attestation that verified but the policy does not admit.
var ErrPolicy = errors.New("attestation not admitted by policy")

func policyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, args...))
}

// Policy decides whether a verified attestation admits an artifact.
type Policy struct {
	// Keys are the trusted signing keys.
	Keys Keyring
	// AllowConditions admits authorized_with_conditions as well as authorized.
	// Off by default: a conditional attestation names untested surfaces that
	// a person accepted, and admitting it is a deliberate choice.
	AllowConditions bool
	// MaxAge, when positive, refuses an attestation issued longer ago.
	MaxAge time.Duration
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Admit verifies env and applies the policy for an artifact whose expected
// digest is sha256. Every refusal names its reason, so a denial message can
// tell an operator what to fix.
func (p Policy) Admit(env []byte, sha256 string) (*Attestation, error) {
	a, err := Verify(env, p.Keys)
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(strings.TrimSpace(sha256))
	if a.SHA256 != want {
		return a, policyErr("attestation is for %s, not the artifact %s", a.SHA256, want)
	}
	switch a.State {
	case StateAuthorized:
	case StateAuthorizedWithConditions:
		if !p.AllowConditions {
			return a, policyErr("attestation is authorized_with_conditions (accepted by %s for %s) and this policy admits only authorized",
				a.AcceptedBy, strings.Join(a.AcceptedSurfaces, ", "))
		}
	default:
		return a, policyErr("attestation state %q does not authorize promotion", a.State)
	}
	if p.MaxAge > 0 {
		issued, err := time.Parse(time.RFC3339, a.IssuedUTC)
		if err != nil {
			return a, policyErr("issued time %q is not RFC 3339, so its age cannot be checked", a.IssuedUTC)
		}
		now := time.Now
		if p.Now != nil {
			now = p.Now
		}
		if age := now().Sub(issued); age > p.MaxAge {
			return a, policyErr("attestation is %s old, over the %s limit; rescan the artifact", age.Round(time.Minute), p.MaxAge)
		}
	}
	return a, nil
}
