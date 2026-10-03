# socair-verify

Verify [Socair](https://socair.ai) model assurance attestations. A small,
dependency-free Go package for consumers such as admission controllers: it
checks an attestation and applies an admission policy, and never scans a model.

An attestation is an [in-toto Statement v1](https://github.com/in-toto/attestation)
whose subject is a model artifact's SHA-256 and whose predicate
(`https://socair.ai/attestation/v1`) is a Socair report, in a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope signed with Ed25519.
It verifies offline, with no transparency log or certificate authority, so it
works in air-gapped clusters.

```go
ring, err := verify.ParseKeyring(operatorPubPEM)
policy := verify.Policy{Keys: ring, MaxAge: 90 * 24 * time.Hour}
att, err := policy.Admit(envelopeBytes, modelSHA256)
if err != nil {
	// errors.Is(err, verify.ErrVerify): not a valid attestation by a trusted key.
	// errors.Is(err, verify.ErrPolicy): valid, but not admitted (another
	// artifact, a withheld or conditional state, too old). The message says why.
}
```

`Verify` checks a signature by a trusted key over the DSSE encoding, the
statement and predicate types and report schema, that the subject digest is the
report's artifact hash, that the report names the key that signed it, and that
the promotion state follows from the report's own checks, so even a trusted
signer cannot attest a state its checks do not support. `Policy.Admit` then
requires the expected digest, an `authorized` state (or
`authorized_with_conditions` when `AllowConditions` is set), and an issue time
within `MaxAge`.

A verified attestation says a trusted key vouched for the report about that
exact artifact. It never certifies more than the report's bounded statement.

Key ids are the hex SHA-256 of the key's PKIX DER encoding, as Socair computes
them. Go 1.26+. License: Apache-2.0.
