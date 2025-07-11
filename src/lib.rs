use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
mod aes;
mod blake2;
mod digital_signature;
mod ed25519;
mod helpers;
mod hmac;
mod rsa;
mod sha;
mod x25519;
mod ascon_aead;
mod zstd;
mod hpke;

pub mod password_hashers {
    pub mod types;
    pub mod argon2;
    pub mod scrypt;
    pub mod bcrypt;
}