package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func operatorRing(t *testing.T) Keyring {
	t.Helper()
	ring, err := ParseKeyring(fixture(t, "operator.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func modelSHA(t *testing.T) string {
	return strings.TrimSpace(string(fixture(t, "model.sha256")))
}

// TestVerifiesSocairOutput: the attestations Socair actually emits verify.
func TestVerifiesSocairOutput(t *testing.T) {
	ring := operatorRing(t)
	for name, state := range map[string]string{
		"authorized.dsse.json":  StateAuthorized,
		"conditional.dsse.json": StateAuthorizedWithConditions,
		"withheld.dsse.json":    StateWithheld,
	} {
		a, err := Verify(fixture(t, name), ring)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a.SHA256 != modelSHA(t) || a.State != state || len(a.Checks) == 0 {
			t.Errorf("%s: sha %s state %s checks %d", name, a.SHA256, a.State, len(a.Checks))
		}
	}
}

// resigned edits a real payload and signs it with a fresh key, returning the
// envelope and a keyring trusting that key. A test uses it to show a check
// other than the signature catches the edit.
func resigned(t *testing.T, name string, edit func(st map[string]any)) ([]byte, Keyring) {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(fixture(t, name), &e); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(e["payload"].(string))
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := KeyID(pub)
	st["predicate"].(map[string]any)["verification"].(map[string]any)["signer_key_id"] = id
	edit(st)
	payload, _ = json.Marshal(st)
	sig := ed25519.Sign(priv, pae(PayloadType, payload))
	e["payload"] = base64.StdEncoding.EncodeToString(payload)
	e["signatures"] = []map[string]string{{"keyid": id, "sig": base64.StdEncoding.EncodeToString(sig)}}
	out, _ := json.Marshal(e)
	return out, Keyring{id: pub}
}

func mustNotVerify(t *testing.T, env []byte, ring Keyring, want string) {
	t.Helper()
	_, err := Verify(env, ring)
	if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), want) {
		t.Fatalf("Verify = %v, want ErrVerify naming %q", err, want)
	}
}

// Each refusal has its own case; skipping the check it names makes that case
// verify.
func TestRefusals(t *testing.T) {
	ring := operatorRing(t)

	t.Run("one flipped bit", func(t *testing.T) {
		var e map[string]any
		_ = json.Unmarshal(fixture(t, "authorized.dsse.json"), &e)
		p, _ := base64.StdEncoding.DecodeString(e["payload"].(string))
		p[len(p)/2] ^= 1
		e["payload"] = base64.StdEncoding.EncodeToString(p)
		b, _ := json.Marshal(e)
		mustNotVerify(t, b, ring, "no valid signature")
	})
	t.Run("untrusted key", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := KeyID(pub)
		mustNotVerify(t, fixture(t, "authorized.dsse.json"), Keyring{id: pub}, "no valid signature by a trusted key")
	})
	t.Run("no trusted keys", func(t *testing.T) {
		mustNotVerify(t, fixture(t, "authorized.dsse.json"), Keyring{}, "no trusted keys")
	})
	t.Run("unsigned", func(t *testing.T) {
		var e map[string]any
		_ = json.Unmarshal(fixture(t, "authorized.dsse.json"), &e)
		e["signatures"] = []any{}
		b, _ := json.Marshal(e)
		mustNotVerify(t, b, ring, "unsigned")
	})
	t.Run("payload type", func(t *testing.T) {
		var e map[string]any
		_ = json.Unmarshal(fixture(t, "authorized.dsse.json"), &e)
		e["payloadType"] = "application/json"
		b, _ := json.Marshal(e)
		mustNotVerify(t, b, ring, "payload type")
	})
	t.Run("subject is another artifact", func(t *testing.T) {
		env, r := resigned(t, "authorized.dsse.json", func(st map[string]any) {
			st["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		})
		mustNotVerify(t, env, r, "subject digest")
	})
	t.Run("predicate type", func(t *testing.T) {
		env, r := resigned(t, "authorized.dsse.json", func(st map[string]any) { st["predicateType"] = "https://example.com/x" })
		mustNotVerify(t, env, r, "predicate type")
	})
	t.Run("signer mismatch", func(t *testing.T) {
		env, r := resigned(t, "authorized.dsse.json", func(st map[string]any) {
			st["predicate"].(map[string]any)["verification"].(map[string]any)["signer_key_id"] = "someone-else"
		})
		mustNotVerify(t, env, r, "names signer")
	})
	t.Run("state the checks do not support", func(t *testing.T) {
		env, r := resigned(t, "withheld.dsse.json", func(st map[string]any) {
			pa := st["predicate"].(map[string]any)["promotion_authorization"].(map[string]any)
			pa["state"], pa["authorized"] = StateAuthorized, true
		})
		mustNotVerify(t, env, r, "NOT_TESTED")
	})
}

func TestPolicy(t *testing.T) {
	ring := operatorRing(t)
	sha := modelSHA(t)
	issued := func(name string) time.Time {
		a, err := Verify(fixture(t, name), ring)
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := time.Parse(time.RFC3339, a.IssuedUTC)
		return ts
	}
	strict := Policy{Keys: ring}

	if _, err := strict.Admit(fixture(t, "authorized.dsse.json"), sha); err != nil {
		t.Fatalf("an authorized attestation for the artifact must be admitted: %v", err)
	}
	if _, err := strict.Admit(fixture(t, "authorized.dsse.json"), strings.Repeat("a", 64)); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "not the artifact") {
		t.Fatalf("an attestation for another artifact must be refused, got %v", err)
	}
	if _, err := strict.Admit(fixture(t, "conditional.dsse.json"), sha); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "ciso@example.com") {
		t.Fatalf("a conditional attestation must be refused by default, naming the acceptor, got %v", err)
	}
	loose := Policy{Keys: ring, AllowConditions: true}
	if _, err := loose.Admit(fixture(t, "conditional.dsse.json"), sha); err != nil {
		t.Fatalf("AllowConditions must admit a conditional attestation: %v", err)
	}
	if _, err := loose.Admit(fixture(t, "withheld.dsse.json"), sha); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "withheld") {
		t.Fatalf("a withheld attestation is never admitted, got %v", err)
	}

	t0 := issued("authorized.dsse.json")
	aged := Policy{Keys: ring, MaxAge: 24 * time.Hour, Now: func() time.Time { return t0.Add(48 * time.Hour) }}
	if _, err := aged.Admit(fixture(t, "authorized.dsse.json"), sha); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "rescan") {
		t.Fatalf("an attestation past MaxAge must be refused, got %v", err)
	}
	fresh := Policy{Keys: ring, MaxAge: 24 * time.Hour, Now: func() time.Time { return t0.Add(time.Hour) }}
	if _, err := fresh.Admit(fixture(t, "authorized.dsse.json"), strings.ToUpper(sha)); err != nil {
		t.Fatalf("a fresh attestation must be admitted, and the digest compared case-insensitively: %v", err)
	}
}

func TestParseKeyringRefusesNothing(t *testing.T) {
	if _, err := ParseKeyring(); err == nil {
		t.Fatal("an empty keyring must be an error")
	}
	if _, err := ParseKeyring([]byte("not a key")); err == nil {
		t.Fatal("garbage must not parse as a key")
	}
}

// FuzzVerify: Verify reads untrusted envelopes, so it may not panic.
func FuzzVerify(f *testing.F) {
	for _, n := range []string{"authorized.dsse.json", "withheld.dsse.json"} {
		b, _ := os.ReadFile(filepath.Join("testdata", n))
		f.Add(b)
	}
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"x","sig":""}]}`))
	ring, _ := ParseKeyring(func() []byte { b, _ := os.ReadFile(filepath.Join("testdata", "operator.pub")); return b }())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Verify(b, ring)
	})
}
