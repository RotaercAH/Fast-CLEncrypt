mod cl;

use crate::cl::clwarpper::*;
use std::time::Instant;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
pub type CU = Secp256k1;
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;
fn main() {
    let g = Point::generator();
    let message_ = FE::from(123);
    let commit = message_ * g;
    let commit_ = commit.to_bytes(true);
    let commit_u8 = commit_.as_ref();
    let commit_str = String::from_utf8_lossy(commit_u8);
    println!("{}", commit_str.to_string());
    let commit_real = "03A598A8030DA6D86C6BC7F2F5144EA549D28211EA58FAA70EBF4C1E665C1FE9B5";
    let message = "123";
    let random = "8394244267790505810968116314215377133223243";
    let sk = "76527095233285027606193913571725252597446671752729";
    //计算公钥
    let pk = public_key_gen(sk.to_string());
    //加密
    let cipher = encrypt(pk.clone(), message.to_string(), random.to_string());
    //解密
    let m = decrypt(sk.to_string(), cipher.clone());
    println!("{}", m);
    // 同态加法
    // 同态数乘
    //零知识证明
    let proof = cl_ecc_prove(pk.clone(), cipher.clone(), commit_real.to_string(), message.to_string(), random.to_string());
    //验证
    let res = cl_ecc_verify(proof.clone(), pk.clone(), cipher.clone(), commit_real.to_string());
    println!("{}", res);
    let start2 = Instant::now();
    for i in 1..100{
    }
    let end2 = Instant::now();
    println!("解密100次运行时间: {:?}", end2 - start2);
}