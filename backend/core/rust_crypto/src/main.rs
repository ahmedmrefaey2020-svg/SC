use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: sentinel_crypto <encrypt|decrypt> <data> <key>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let data = &args[2];
    let key = &args[3];

    match mode.as_str() {
        "encrypt" => {
            let data_c = std::ffi::CString::new(data.as_str()).unwrap();
            let key_c = std::ffi::CString::new(key.as_str()).unwrap();
            let res_ptr = sentinel_crypto::encrypt_payload(data_c.as_ptr(), key_c.as_ptr());
            let res = unsafe { std::ffi::CStr::from_ptr(res_ptr).to_string_lossy().into_owned() };
            println!("{}", res);
            sentinel_crypto::free_string(res_ptr);
        }
        "decrypt" => {
            let data_c = std::ffi::CString::new(data.as_str()).unwrap();
            let key_c = std::ffi::CString::new(key.as_str()).unwrap();
            let res_ptr = sentinel_crypto::decrypt_payload(data_c.as_ptr(), key_c.as_ptr());
            let res = unsafe { std::ffi::CStr::from_ptr(res_ptr).to_string_lossy().into_owned() };
            println!("{}", res);
            sentinel_crypto::free_string(res_ptr);
        }
        _ => {
            eprintln!("Invalid mode");
            std::process::exit(1);
        }
    }
}
