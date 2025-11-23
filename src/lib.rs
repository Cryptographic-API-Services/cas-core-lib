use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
pub mod aes;
pub mod blake2;
pub mod digital_signature;
pub mod ed25519;
pub mod helpers;
pub mod hmac;
pub mod rsa;
pub mod sha;
pub mod x25519;
pub mod ascon_aead;
pub mod zstd;
pub mod hpke;
pub mod pqc {
    pub mod slh_dsa;
    pub mod types;
}

pub mod password_hashers {
    pub mod types;
    pub mod argon2;
    pub mod scrypt;
    pub mod bcrypt;
}

pub mod benchmark_http {
    pub mod http;
}