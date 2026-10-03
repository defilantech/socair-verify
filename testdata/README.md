These attestations were produced by the Socair CLI (`socair scan`, then
`socair sign`) over a 32-byte safetensors file whose SHA-256 is in
`model.sha256`, signed by the key in `operator.pub`. They are the real
producer's bytes, so the tests pin the wire contract rather than a copy of it.
The matching private key is not committed; tests that need to sign generate
their own key.
