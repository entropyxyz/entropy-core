# Protocol Implementation
See [HackMD spec](https://hackmd.io/kLiqrFYETOiONBYXIdqdMA?view) for details.

## Current Block: Dependency failing to compile
Run:
RUSTFLAGS="-Z macro-backtrace" cargo +nightly check

Will fail with a complaint about Zeroize. How fix?

```
   |
26 |   #[derive(Zeroize)]
   |            ^^^^^^^
   |            |
   |            not found in `zeroize`
   |            in this derive macro expansion
   |
  ::: /home/thor/.cargo/registry/src/github.com-1ecc6299db9ec823/synstructure-0.12.6/src/macros.rs:94:9
   |
94 | /         pub fn $derives(
95 | |             i: $crate::macros::TokenStream
96 | |         ) -> $crate::macros::TokenStream {
   | |________________________________________- in this expansion of `#[derive(Zeroize)]`

```
