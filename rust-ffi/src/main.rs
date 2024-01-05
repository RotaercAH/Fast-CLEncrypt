extern crate libc;

use libc::c_char;
use std::ffi::{CString, CStr};
use std::time::Instant;
use encoding::{DecoderTrap, Encoding};
use encoding::all::GBK;

#[link(name = "encrypt")]
extern "C" {
    pub fn encrypt_and_decrypt_test(message: *const c_char) -> *const c_char;
    pub fn public_key_gen(sk_str: *const c_char) -> *const c_char;
    pub fn encrypt(pk_str: *const c_char, message: *const c_char) -> *const c_char;
    pub fn decrypt(sk_str: *const c_char, cipher_str: *const c_char) -> *const c_char;
}

pub fn public_key_gen_rust(sk: String) -> String {
    let sk_str = CString::new(sk).unwrap();
    let sk_ptr: *const c_char = sk_str.as_ptr();
    unsafe{
        let mut msgstr: String = "".to_string();
        let out = public_key_gen(sk_ptr);
        if out != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(out);
            let errcstr_tostr = errcstr.to_str();
            //这里要处理下编码，rust默认是UTF-8,如果不ok，那就是其他字符集
            if errcstr_tostr.is_ok() {
                msgstr = errcstr_tostr.unwrap().to_string();
            } else {
                //强行尝试对CStr对象进行GBK解码,采用replace策略
                //todo: 如果在使用其他编码的平台上依旧有可能失败，得到空消息，但不会抛异常了
                let alter_msg = GBK.decode(errcstr.to_bytes(), DecoderTrap::Replace);
                // let alter_msg = encoding::all::UTF_8.decode(errcstr.to_bytes(),DecoderTrap::Replace);
                if alter_msg.is_ok() {
                    msgstr = alter_msg.unwrap();
                }
            }
        }
        return msgstr;
    }
}

pub fn encrypt_rust(pk: String, message: String) -> String{
    let pk_str = CString::new(pk).unwrap();
    let pk_ptr: *const c_char = pk_str.as_ptr();
    let m_str = CString::new(message).unwrap();
    let m_ptr: *const c_char = m_str.as_ptr();
    unsafe{
        let mut msgstr: String = "".to_string();
        let out = encrypt(pk_ptr, m_ptr);
        if out != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(out);
            let errcstr_tostr = errcstr.to_str();
            //这里要处理下编码，rust默认是UTF-8,如果不ok，那就是其他字符集
            if errcstr_tostr.is_ok() {
                msgstr = errcstr_tostr.unwrap().to_string();
            } else {
                //强行尝试对CStr对象进行GBK解码,采用replace策略
                //todo: 如果在使用其他编码的平台上依旧有可能失败，得到空消息，但不会抛异常了
                let alter_msg = GBK.decode(errcstr.to_bytes(), DecoderTrap::Replace);
                // let alter_msg = encoding::all::UTF_8.decode(errcstr.to_bytes(),DecoderTrap::Replace);
                if alter_msg.is_ok() {
                    msgstr = alter_msg.unwrap();
                }
            }
        }
        return msgstr;
    }
}

pub fn decrypt_rust(sk: String, cipher: String) -> String{
    let sk_str = CString::new(sk).unwrap();
    let sk_ptr: *const c_char = sk_str.as_ptr();
    let c_str = CString::new(cipher).unwrap();
    let c_ptr: *const c_char = c_str.as_ptr();
    unsafe{
        let mut msgstr: String = "".to_string();
        let out = decrypt(sk_ptr, c_ptr);
        if out != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(out);
            let errcstr_tostr = errcstr.to_str();
            //这里要处理下编码，rust默认是UTF-8,如果不ok，那就是其他字符集
            if errcstr_tostr.is_ok() {
                msgstr = errcstr_tostr.unwrap().to_string();
            } else {
                //强行尝试对CStr对象进行GBK解码,采用replace策略
                //todo: 如果在使用其他编码的平台上依旧有可能失败，得到空消息，但不会抛异常了
                let alter_msg = GBK.decode(errcstr.to_bytes(), DecoderTrap::Replace);
                // let alter_msg = encoding::all::UTF_8.decode(errcstr.to_bytes(),DecoderTrap::Replace);
                if alter_msg.is_ok() {
                    msgstr = alter_msg.unwrap();
                }
            }
        }
        return msgstr;
    }
}

pub fn encrypt_and_decrypt_test_rust(message: String){
    let m_str = CString::new(message).unwrap();
    let m_prt: *const c_char = m_str.as_ptr();
    // let message = "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d";
    unsafe{
        let mut msgstr: String = "".to_string();
        let out = encrypt_and_decrypt_test(m_prt);
        if out != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(out);
            let errcstr_tostr = errcstr.to_str();
            //这里要处理下编码，rust默认是UTF-8,如果不ok，那就是其他字符集
            if errcstr_tostr.is_ok() {
                msgstr = errcstr_tostr.unwrap().to_string();
            } else {
                //强行尝试对CStr对象进行GBK解码,采用replace策略
                //todo: 如果在使用其他编码的平台上依旧有可能失败，得到空消息，但不会抛异常了
                let alter_msg = GBK.decode(errcstr.to_bytes(), DecoderTrap::Replace);
                // let alter_msg = encoding::all::UTF_8.decode(errcstr.to_bytes(),DecoderTrap::Replace);
                if alter_msg.is_ok() {
                    msgstr = alter_msg.unwrap();
                }
            }
        }
        println!("{msgstr}");
    }
}

fn main() {
    let message = "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede";
    // let message = "660c690db8f30933d27f482f";
    let sk = "4731285847384423928591964720523";
    let pk = public_key_gen_rust(sk.to_string());
    println!("pk_rust: {pk}");
    let cipher = encrypt_rust(pk.clone(), message.to_string());
    let start1 = Instant::now();
    for i in 1..100{
        let cipher = encrypt_rust(pk.clone(), message.to_string());
    }
    let end1 = Instant::now();
    println!("加密100次运行时间： {:?}", end1 - start1);
    let start2 = Instant::now();
    for i in 1..100{
        let m = decrypt_rust(sk.to_string(), cipher.clone());
    }
    let end2 = Instant::now();
    println!("解密100次运行时间： {:?}", end2 - start2);
}