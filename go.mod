module mpc-go-demo

go 1.25.5

replace github.com/taurusgroup/multi-party-sig => github.com/taurushq-io/multi-party-sig v0.7.0-alpha-2025-01-28

require (
	filippo.io/edwards25519 v1.1.0
	github.com/cronokirby/saferith v0.33.0
	github.com/taurusgroup/multi-party-sig v0.7.0-alpha-2025-01-28
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)
