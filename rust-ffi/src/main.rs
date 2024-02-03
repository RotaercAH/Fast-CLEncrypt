mod cl;

use crate::cl::clwarpper::*;
use std::time::Instant;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
pub type CU = Secp256k1;
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;
use encoding::codec::utf_16::Big;
use num_bigint::BigUint;
// use num_traits::Num;


fn main() {
    // let g = Point::generator();
    let message = FE::random();
    println!("message: {}", message.to_bigint().to_string());
    
    let m_bn = BigInt::from_hex("e82bd06a91f7d6125406289d6b4d8a697700c7d681bfc9e898be202f1b4888cb").unwrap();
    let m_fe = FE::from_bigint(&m_bn);
    println!("message_fe2str: {}", m_fe.to_bigint().to_string());
    let m_str = to_hex("12".to_string());
    println!("m_str: {}", m_str);

    let decimal_str = "107099559641330179244670976738667050804447623953856111728439781080547065630320";
    let mut hex_str = String::new();
    // 将十进制字符串转换为BigUint
    if let Ok(decimal_num) = decimal_str.parse::<BigUint>() {
        hex_str = format!("{:x}", decimal_num);
    }else{

    }
    
    println!("十六进制字符串: {}", hex_str);

    // let commit = message.clone() * g;
    // let commit_str = to_hex(commit.to_bytes(true).as_ref());
    let random = FE::random().to_bigint().to_string();
    println!("random: {}", random);
    let sk = FE::random().to_bigint().to_string();
    let sk1 = FE::random();
    println!("sk1: {}", sk1.to_bigint().to_string());
    let sk2 = FE::random();
    println!("sk2: {}", sk2.to_bigint().to_string());
    let sk_total = sk1 + sk2;
    println!("sk_total: {}", sk_total.to_bigint().to_string());
    
    //计算公钥
    let qfi = "184983538100188845410697144839304481634 1 -2028728280155228797 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    let mut start = Instant::now();
    for i in 1..10000{
        qfi_add(qfi.to_string(), qfi.to_string());
    }
    let mut end = Instant::now();
    println!("cl add 10000次运行时间: {:?}", end - start);

    start = Instant::now();
    for i in 1..10000{
        qfi_mul(qfi.to_string(), sk.clone());
    }
    end = Instant::now();
    println!("cl mul 10000次运行时间: {:?}", end - start);
    /* 
    //加密
    let cipher = encrypt(pk.clone(), message.to_bigint().to_string(), random.clone());
    //解密
    let m = decrypt(sk.to_string(), cipher.clone());
    println!("m: {}", m);
    // 同态加法
    let cipher1 = encrypt(pk.clone(), "123".to_string(), random.clone());
    let cipher2 = encrypt(pk.clone(), "4".to_string(), random.clone());
    let cipher_add = add_ciphertexts(cipher1.clone(), cipher2.clone());
    let m_add = decrypt(sk.clone(), cipher_add.clone());
    println!("add: {}", m_add);
    // 同态数乘
    let cipher_scal = scal_ciphertexts( cipher1.clone(), "3".to_string());
    let m_scal = decrypt(sk.clone(), cipher_scal.clone());
    println!("scal: {}", m_scal);
    //加密正确零知识证明
    let encrypt_proof = encrypt_prove(pk.clone(), cipher.clone(), message.to_bigint().to_string(), random.clone());
    //加密正确验证
    let res1 = encrypt_verify(encrypt_proof.clone(), pk.clone(), cipher.clone());
    println!("encrypt verify res: {}", res1);
    //密文承诺零知识证明
    let cl_ecc_proof = cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_bigint().to_string(), random.clone());
    //密文承诺验证
    let res2 = cl_ecc_verify(cl_ecc_proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    println!("cl ecc verify res: {}", res2);
    //密文相等零知识证明
    let sk_ = FE::random().to_bigint().to_string();
    let pk_ = public_key_gen(sk_.clone());
    let random_ = FE::random().to_bigint().to_string();
    let cipher_ = encrypt(pk_.clone(), message.to_bigint().to_string(), random_.clone());
    let cl_cl_proof = cl_cl_prove(pk.clone(), pk_.clone(), cipher.clone(), cipher_.clone(),message.to_bigint().to_string(), random.clone(), random_.clone());
    //密文相等验证
    let res3 = cl_cl_verify(cl_cl_proof.clone(), pk.clone(), pk_.clone(),cipher.clone(), cipher_.clone());
    println!("cl ecc verify res: {}", res3);
    //公钥生成效率
    let mut start = Instant::now();
    for i in 1..100{
        public_key_gen(sk.clone());
    }
    let mut end = Instant::now();
    println!("公钥生成100次运行时间: {:?}", end - start);

    //加密效率
    start = Instant::now();
    for i in 1..100{
        encrypt(pk.clone(), message.to_bigint().to_string(), random.to_string());
    }
    end = Instant::now();
    println!("加密100次运行时间: {:?}", end - start);

    //解密效率
    start = Instant::now();
    for i in 1..100{
       decrypt(sk.to_string(), cipher.clone());
    }
    end = Instant::now();
    println!("解密100次运行时间: {:?}", end - start);

    //同态加法效率
    start = Instant::now();
    for i in 1..100{
        add_ciphertexts(cipher1.clone(), cipher2.clone());
    }
    end = Instant::now();
    println!("同态加法100次运行时间: {:?}", end - start);

    //加密正确零知识证明效率
    start = Instant::now();
    for i in 1..100{
        encrypt_prove(pk.clone(), cipher.clone(), message.to_bigint().to_string(), random.clone());
    }
    end = Instant::now();
    println!("加密正确证明100次运行时间: {:?}", end - start);

    //加密正确零知识证明验证效率
    start = Instant::now();
    for i in 1..100{
        encrypt_verify(encrypt_proof.clone(), pk.clone(), cipher.clone());
    }
    end = Instant::now();
    println!("加密正确验证100次运行时间: {:?}", end - start);

    //加密承诺零知识证明效率
    start = Instant::now();
    for i in 1..100{
       cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_bigint().to_string(), random.to_string());
    }
    end = Instant::now();
    println!("加密承诺证明100次运行时间: {:?}", end - start);

    //加密承诺零知识证明验证效率
    start = Instant::now();
    for i in 1..100{
        cl_ecc_verify(cl_ecc_proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    }
    end = Instant::now();
    println!("加密承诺验证100次运行时间: {:?}", end - start);

     //密文相等零知识证明效率
     start = Instant::now();
     for i in 1..100{
        cl_cl_prove(pk.clone(), pk_.clone(), cipher.clone(), cipher_.clone(),message.to_bigint().to_string(), random.clone(), random_.clone());
     }
     end = Instant::now();
     println!("密文相等证明100次运行时间: {:?}", end - start);
 
     //密文相等零知识证明验证效率
     start = Instant::now();
     for i in 1..100{
        cl_cl_verify(cl_cl_proof.clone(), pk.clone(), pk_.clone(),cipher.clone(), cipher_.clone());
     }
     end = Instant::now();
     println!("密文相等验证100次运行时间: {:?}", end - start);
     */
}