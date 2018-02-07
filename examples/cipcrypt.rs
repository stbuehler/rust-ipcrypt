/// export C interface
extern crate ipcrypt;

#[no_mangle]
pub unsafe extern "C" fn ipcrypt_encrypt(v: u32, key: *const u8) -> u32 {
	let key = ::std::mem::transmute::<*const u8, &ipcrypt::Key>(key);
	ipcrypt::encrypt(v, key)
}

#[no_mangle]
pub unsafe extern "C" fn ipcrypt_decrypt(v: u32, key: *const u8) -> u32 {
	let key = ::std::mem::transmute::<*const u8, &ipcrypt::Key>(key);
	ipcrypt::decrypt(v, key)
}
