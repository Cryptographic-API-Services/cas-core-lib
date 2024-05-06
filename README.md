# cas-core-lib

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/7bXXCQj45q)

## Overview
This is our experimental core library which provides a simple FFI layer that takes advantage of Rust's thread safe nature to provide an abstraction layer to higher level languages to run industry standard crytographic operations sequentially and in parallel. Our goal is to decrease the redundancy of engineer's creating this layer proprietary within their internal systems. 

## Consuming Library Documentation
We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)
- [Rayon](https://github.com/rayon-rs/rayon)


## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](./src) have never had a security audit performed. Utilize this SDK at your own risk.
