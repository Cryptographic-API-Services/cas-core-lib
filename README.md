# cas-core-lib

## Overview
This is our experimental core library which provides a simple FFI layer that takes advantage of Rust's thread safe nature to provide an abstraction layer to higher level languages to run industry standard crytographic operations sequentially, on threads, and the thread pool. Our goal is to decrease the redundancy of engineer's creating this layer proprietary within their internal systems. 

## Consuming Library Documentation
We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)
- [Rayon](https://github.com/rayon-rs/rayon)
