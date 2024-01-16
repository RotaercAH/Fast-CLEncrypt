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
    let message = FE::random();
    let commit = message.clone() * g;
    let commit_str = to_hex(commit.to_bytes(true).as_ref());
    let random = FE::random().to_bigint().to_string();
    println!("random: {}", random);
    let sk = FE::random().to_bigint().to_string();
    //计算公钥
    let pk = public_key_gen(sk.clone());
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
    //零知识证明
    let proof = cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_bigint().to_string(), random.clone());
    //验证
    let res = cl_ecc_verify(proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    println!("verify res: {}", res);
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

    //零知识证明效率
    start = Instant::now();
    for i in 1..100{
       cl_ecc_prove(pk.clone(), cipher.clone(), commit_str.clone(), message.to_bigint().to_string(), random.to_string());
    }
    end = Instant::now();
    println!("证明100次运行时间: {:?}", end - start);

    //零知识证明验证效率
    start = Instant::now();
    for i in 1..100{
        cl_ecc_verify(proof.clone(), pk.clone(), cipher.clone(), commit_str.clone());
    }
    end = Instant::now();
    println!("验证100次运行时间: {:?}", end - start);
}