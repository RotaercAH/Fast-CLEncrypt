mod cl;

use crate::cl::clwarpper::*;
use std::time::Instant;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
pub type CU = Secp256k1;
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

static HEX_TABLE :[char;16] = ['0','1','2','3','4','5','6','7','8','9',
                                        'A','B','C','D','E','F'];

fn to_hex(data : impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let len = data.len();
    let mut res = String::with_capacity(len * 2);

    for i in 0..len {
        res.push(HEX_TABLE[usize::from(data[i] >> 4)] );
        res.push(HEX_TABLE[usize::from(data[i] & 0x0F)]);
    }
    res
}

fn main() {
    let g = Point::generator();
    let message = "123";
    let message_ = FE::from(123);
    let commit = message_ * g;
    let commit_str = to_hex(commit.to_bytes(true).as_ref());
    let random = "839424426779050581096811631421537713322";
    let sk = "76527095233285027606193913571725252597446671752729";
    //计算公钥
    let pk = public_key_gen(sk.to_string());
    //加密
    let cipher = encrypt(pk.clone(), message.to_string(), random.to_string());
    //解密
    let m = decrypt(sk.to_string(), cipher.clone());
    println!("m: {}", m);
    // 同态加法
    let cipher1 = encrypt(pk.clone(), "123".to_string(), random.to_string());
    let cipher2 = encrypt(pk.clone(), "4".to_string(), random.to_string());
    let cipher_add = add_ciphertexts(pk.clone(), cipher1.clone(), cipher2.clone());
    let m_add = decrypt(sk.to_string(), cipher_add.clone());
    println!("add: {}", m_add);
    // 同态数乘
    let cipher_scal = scal_ciphertexts(pk.clone(), cipher1.clone(), "3".to_string());
    let m_scal = decrypt(sk.to_string(), cipher_scal.clone());
    println!("scal: {}", m_scal);
    //零知识证明
    let proof = cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_string(), random.to_string());
    //验证
    let res = cl_ecc_verify(proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    println!("verify res: {}", res);
    //加密效率
    let mut start = Instant::now();
    for i in 1..100{
        let cipher_test = encrypt(pk.clone(), message.to_string(), random.to_string());
    }
    let mut end = Instant::now();
    println!("加密100次运行时间: {:?}", end - start);
    //解密效率
    start = Instant::now();
    for i in 1..100{
        let m_test = decrypt(sk.to_string(), cipher.clone());
    }
    end = Instant::now();
    println!("解密100次运行时间: {:?}", end - start);
    //零知识证明效率
    start = Instant::now();
    for i in 1..100{
        let proof_test = cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_string(), random.to_string());
    }
    end = Instant::now();
    println!("证明100次运行时间: {:?}", end - start);
    //零知识证明验证效率
    start = Instant::now();
    for i in 1..100{
        let res_test = cl_ecc_verify(proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    }
    end = Instant::now();
    println!("验证100次运行时间: {:?}", end - start);
}