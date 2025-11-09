
# CAS Core Lib (Rust)

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/UAGqKfmvUS)

## Overview
CAS Core Lib is a comprehensive cryptographic toolkit for Rust, designed to provide a unified, high-level FFI interface to industry-standard cryptographic algorithms. This library acts as the foundation for higher-level SDKs (such as our .NET implementation), enabling secure and efficient cryptographic operations through a simple, consistent API.

CAS Core Lib abstracts over trusted, open-source cryptography libraries, including RustCrypto and Dalek-Cryptography, to deliver modern cryptographic primitives and utilities for cross-language integration.

## Features
- Modern cryptographic primitives: digital signatures (RSA, Ed25519), hashing, symmetric encryption, and more
- Simple FFI layer for seamless integration with .NET, TypeScript, and other languages
- Unified interface: no need to manage multiple cryptography packages or disparate documentation
- Built on trusted, open-source cryptography libraries
- Cross-platform support: Linux x64, Windows x64 (via FFI consumers)
- Designed for performance, safety, and extensibility

## Documentation & References
CAS Core Lib builds on the work of leading cryptography projects. For in-depth algorithm details and implementation notes, please refer to:
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Usage Examples
Practical usage and code samples are available in the documentation of consumer SDKs (e.g., .NET, TypeScript). For direct FFI usage, see the exported functions in [`src/lib.rs`](./src/lib.rs).

## Supported Platforms / Operating Systems
CAS Core Lib is tested and maintained for cross-compatibility. Consumer SDKs run test cases on major platforms and frameworks:
- [X] Linux x64
- [X] Windows x64
- [X] .NET 6, 7, 8, 9 (via FFI)
- [X] Node.js / TypeScript (via FFI)

## Disclaimer
This library leverages several cryptographic crates via our core FFI [layer](./src). Please note that many of these crates have not undergone formal security audits. Use this library at your own risk and always review the underlying cryptographic implementations for your security requirements.

---
For questions, support, or to contribute, join our Discord or visit the [GitHub organization](https://github.com/Cryptographic-API-Services).
