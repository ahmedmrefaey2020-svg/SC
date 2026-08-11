use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;

#[no_mangle]
pub extern "C" fn encrypt_payload(data: *const c_char, key_str: *const c_char) -> *mut c_char {
    if data.is_null() || key_str.is_null() {
        return CString::new("").unwrap().into_raw();
    }
    
    let c_data = unsafe { CStr::from_ptr(data) };
    let c_key = unsafe { CStr::from_ptr(key_str) };
    
    let data_bytes = c_data.to_bytes();
    let raw_key = c_key.to_bytes();
    
    let mut key_bytes = [0u8; 32];
    for (i, &b) in raw_key.iter().enumerate().take(32) {
        key_bytes[i] = b;
    }
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    match cipher.encrypt(nonce, data_bytes) {
        Ok(ciphertext) => {
            let mut result = Vec::new();
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            let encoded = BASE64.encode(result);
            CString::new(encoded).unwrap_or_default().into_raw()
        }
        Err(_) => CString::new("").unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn decrypt_payload(encrypted_data: *const c_char, key_str: *const c_char) -> *mut c_char {
    if encrypted_data.is_null() || key_str.is_null() {
        return CString::new("").unwrap().into_raw();
    }
    
    let c_enc = unsafe { CStr::from_ptr(encrypted_data) };
    let c_key = unsafe { CStr::from_ptr(key_str) };
    
    let enc_str = match c_enc.to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };
    
    let decoded = match BASE64.decode(enc_str) {
        Ok(d) => d,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };
    
    if decoded.len() < 12 {
        return CString::new("").unwrap().into_raw();
    }
    
    let nonce_bytes = &decoded[0..12];
    let ciphertext = &decoded[12..];
    
    let raw_key = c_key.to_bytes();
    let mut key_bytes = [0u8; 32];
    for (i, &b) in raw_key.iter().enumerate().take(32) {
        key_bytes[i] = b;
    }
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => {
            CString::new(plaintext).unwrap_or_default().into_raw()
        }
        Err(_) => CString::new("").unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
