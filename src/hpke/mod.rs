use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use types::HpkeKeyPair;

mod types;

#[no_mangle]
pub extern "C" fn hpke_generate_keypair() -> HpkeKeyPair {
    let (mut private_key, mut public_key) = <CASHPKE as CASHybrid>::generate_key_pair();
    let private_key_capacity = private_key.capacity();
    private_key.reserve_exact(private_key_capacity);
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let return_result = HpkeKeyPair {
        private_key_ptr: private_key.as_mut_ptr(),
        private_key_ptr_length: private_key.len(),
        public_key_ptr: public_key.as_mut_ptr(),
        public_key_ptr_length: public_key.len()
    };
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    return_result
}