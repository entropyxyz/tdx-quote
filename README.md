# `tdx-quote`

Parses and verifies Intel TDX quotes (v4 and v5)

This crate is `no_std`.

This is inspired by [tdx-quote-parser](https://github.com/MoeMahhouk/tdx-quote-parser) for the types
and [sgx-quote](https://docs.rs/sgx-quote) for the no-std parsing using [nom](https://docs.rs/nom).

This is based on the specification described in the [Intel TDX DCAP Quoting Library API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf),
appendix 3.

The `mock` feature flag allows generating mock quotes, which this library can parse and verify. This
is used for testing attestation features on without needing TDX hardware.

Warning: This is in early stages of development and has not been audited.

For quote generation, see [`configfs-tsm`](https://crates.io/crates/configfs-tsm).
