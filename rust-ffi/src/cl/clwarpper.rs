extern crate libc;

use libc::c_char;
use std::ffi::{CString, CStr};
use encoding::{DecoderTrap, Encoding};
use encoding::all::GBK;

static HEX_TABLE :[char;16] = ['0','1','2','3','4','5','6','7','8','9',
                                        'A','B','C','D','E','F'];

#[link(name = "encrypt")]
extern "C" {
    pub fn public_key_gen_cpp(sk_str: *const c_char) -> *const c_char;
    pub fn encrypt_cpp(pk_str: *const c_char, message: *const c_char, random: *const c_char) -> *const c_char;
    pub fn decrypt_cpp(sk_str: *const c_char, cipher_str: *const c_char) -> *const c_char;
    pub fn add_ciphertexts_cpp(cipher_str_first: *const c_char, cipher_str_second: *const c_char) -> *const c_char;
    pub fn scal_ciphertexts_cpp(cipher_str: *const c_char, m_str: *const c_char) -> *const c_char;
    pub fn encrypt_prove_cpp(pk_str: *const c_char, cipher_str: *const c_char, m_str: *const c_char, r_str: *const c_char) -> *const c_char;
    pub fn encrypt_verify_cpp(proof_str: *const c_char, pk_str: *const c_char, cipher_str: *const c_char) -> *const c_char;
    pub fn cl_ecc_prove_cpp(pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char, m_str: *const c_char, r_str: *const c_char) -> *const c_char;
    pub fn cl_ecc_verify_cpp(proof_str: *const c_char, pk_str: *const c_char, cipher_str: *const c_char , commit_str: *const c_char) -> *const c_char;
    pub fn cl_cl_prove_cpp(pk1_str: *const c_char, pk2_str: *const c_char, cipher1_str: *const c_char, cipher2_str: *const c_char, m_str: *const c_char, r1_str: *const c_char, r2_str: *const c_char) -> *const c_char;
    pub fn cl_cl_verify_cpp(proof_str: *const c_char, pk1_str: *const c_char, pk2_str: *const c_char, cipher1_str: *const c_char , cipher2_str: *const c_char) -> *const c_char;
    pub fn qfi_add_cpp(qfi1_str: *const c_char, qfi2_str: *const c_char) -> *const c_char;
    pub fn qfi_mul_cpp(qfi_str: *const c_char, mpz_str: *const c_char) -> *const c_char;
}

pub fn c_char_decode(input: *const i8) -> String {
    unsafe{
        let mut msgstr: String = "".to_string();
        if input != (0 as *mut c_char) {
            let errcstr = CStr::from_ptr(input);
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

pub fn public_key_gen(sk: String) -> String {
    let sk_str = CString::new(sk).unwrap();
    unsafe{
        return c_char_decode(public_key_gen_cpp(sk_str.as_ptr()));
    }
}

pub fn encrypt(pk: String, message: String, random: String) -> String{
    let pk_str = CString::new(pk).unwrap();
    let m_str = CString::new(message).unwrap();
    let r_str = CString::new(random).unwrap();
    unsafe{
        return c_char_decode(encrypt_cpp(pk_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn decrypt(sk: String, cipher: String) -> String{
    let sk_str = CString::new(sk).unwrap();
    let c_str = CString::new(cipher).unwrap();
    unsafe{
        return c_char_decode(decrypt_cpp(sk_str.as_ptr(), c_str.as_ptr()));
    }
}

pub fn add_ciphertexts(cipher_first: String, cipher_second: String) -> String{
    let c_first_str = CString::new(cipher_first).unwrap();
    let c_second_str = CString::new(cipher_second).unwrap();
    unsafe{
        return c_char_decode(add_ciphertexts_cpp(c_first_str.as_ptr(), c_second_str.as_ptr()));
    }
}

pub fn scal_ciphertexts(cipher: String, message: String) -> String{
    let c_str = CString::new(cipher).unwrap();
    let m_str = CString::new(message).unwrap();
    unsafe{
        return c_char_decode(scal_ciphertexts_cpp(c_str.as_ptr(), m_str.as_ptr()));
    }
}

pub fn encrypt_prove(pk: String, cipher: String, message: String, random: String)-> String{
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let m_str =  CString::new(message).unwrap();
    let r_str =  CString::new(random).unwrap();
    unsafe{
        return c_char_decode(encrypt_prove_cpp(pk_str.as_ptr(), c_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn encrypt_verify(proof: String, pk: String, cipher: String)-> String{
    let proof_str = CString::new(proof).unwrap();
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    unsafe{
        return c_char_decode(encrypt_verify_cpp(proof_str.as_ptr(), pk_str.as_ptr(), c_str.as_ptr()));
    }
}

pub fn cl_ecc_prove(pk: String, cipher: String, commit: String, message: String, random: String)-> String{
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    let m_str =  CString::new(message).unwrap();
    let r_str =  CString::new(random).unwrap();
    unsafe{
        return c_char_decode(cl_ecc_prove_cpp(pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr(), m_str.as_ptr(), r_str.as_ptr()));
    }
}

pub fn cl_ecc_verify(proof: String, pk: String, cipher: String, commit: String)-> String{
    let proof_str = CString::new(proof).unwrap();
    let pk_str= CString::new(pk).unwrap();
    let c_str =  CString::new(cipher).unwrap();
    let commit_str =  CString::new(commit).unwrap();
    unsafe{
        return c_char_decode(cl_ecc_verify_cpp(proof_str.as_ptr(), pk_str.as_ptr(), c_str.as_ptr(), commit_str.as_ptr()));
    }
}

pub fn cl_cl_prove(pk1: String, pk2: String, cipher1: String, cipher2: String, message: String, random1: String, random2: String)-> String{
    let pk1_str= CString::new(pk1).unwrap();
    let pk2_str= CString::new(pk2).unwrap();
    let c1_str =  CString::new(cipher1).unwrap();
    let c2_str =  CString::new(cipher2).unwrap();
    let m_str =  CString::new(message).unwrap();
    let r1_str =  CString::new(random1).unwrap();
    let r2_str =  CString::new(random2).unwrap();
    unsafe{
        return c_char_decode(cl_cl_prove_cpp(pk1_str.as_ptr(), pk2_str.as_ptr(),c1_str.as_ptr(), c2_str.as_ptr(),  m_str.as_ptr(), r1_str.as_ptr(), r2_str.as_ptr()));
    }
}

pub fn cl_cl_verify(proof: String, pk1: String, pk2: String, cipher1: String, cipher2: String)-> String{
    let proof_str = CString::new(proof).unwrap();
    let pk1_str= CString::new(pk1).unwrap();
    let pk2_str= CString::new(pk2).unwrap();
    let c1_str =  CString::new(cipher1).unwrap();
    let c2_str =  CString::new(cipher2).unwrap();
    unsafe{
        return c_char_decode(cl_cl_verify_cpp(proof_str.as_ptr(), pk1_str.as_ptr(), pk2_str.as_ptr(), c1_str.as_ptr(), c2_str.as_ptr()));
    }
}

pub fn qfi_add(qfi1: String, qfi2: String)-> String{
    let qfi1_str = CString::new(qfi1).unwrap();
    let qfi2_str= CString::new(qfi2).unwrap();
    unsafe{
        return c_char_decode(qfi_add_cpp(qfi1_str.as_ptr(), qfi2_str.as_ptr()));
    }
}

pub fn qfi_mul(qfi: String, mpz: String)-> String{
    let qfi_str = CString::new(qfi).unwrap();
    let mpz_str= CString::new(mpz).unwrap();
    unsafe{
        return c_char_decode(qfi_mul_cpp(qfi_str.as_ptr(), mpz_str.as_ptr()));
    }
}

pub fn to_hex(data : impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let len = data.len();
    let mut res = String::with_capacity(len * 2);

    for i in 0..len {
        res.push(HEX_TABLE[usize::from(data[i] >> 4)] );
        res.push(HEX_TABLE[usize::from(data[i] & 0x0F)]);
    }
    res
}
