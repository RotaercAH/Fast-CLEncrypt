extern crate libc;

use libc::c_char;
use std::ffi::{CString, CStr};
use encoding::{DecoderTrap, Encoding};
use encoding::all::GBK;

#[link(name = "encrypt")]
extern "C" {
    pub fn encrypt_and_decrypt_test(message: *const c_char) -> *const c_char;
}

fn main() {
    let m_str = CString::new(b"660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125edeaa" as &[u8]).unwrap();
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
    println!("Hello, world!");
}