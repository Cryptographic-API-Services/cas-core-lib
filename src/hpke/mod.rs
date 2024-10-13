use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use types::HpkeKeyPair;

mod types;

#[no_mangle]
pub extern "C" fn hpke_generate_keypair() -> HpkeKeyPair {
    let (mut private_key, mut public_key, mut info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    let private_key_capacity = private_key.capacity();
    private_key.reserve_exact(private_key_capacity);
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let info_str_capacity = info_str.capacity();
    info_str.reserve_exact(info_str_capacity);
    let return_result = HpkeKeyPair {
        private_key_ptr: private_key.as_mut_ptr(),
        private_key_ptr_length: private_key.len(),
        public_key_ptr: public_key.as_mut_ptr(),
        public_key_ptr_length: public_key.len(),
        info_str_ptr: info_str.as_mut_ptr(),
        info_str_ptr_length: info_str.len()
    };
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(info_str);
    return_result
}