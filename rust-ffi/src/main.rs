mod cl;

use crate::cl::clwarpper::*;
use std::time::Instant;
use curv::elliptic::curves::{Point, Scalar, Secp256k1, Secp256r1, Ed25519};
pub type CU = Secp256k1;
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;
fn main() {
    let g = Point::generator();
    let g_str = g.to_bytes(false);
    println!("g: {:?}", g_str.as_ref());
    let message_ = FE::from(123);
    let commit = message_ * g;
    let commit_str = commit.to_bytes(true);
    println!("commit: {:?}", commit_str.as_ref());
    // let  FE::random();
    let message = "11111111";
    let random = "83942442677905058109681163142153771332232435819780612172664980548506215620367";
    // let message = "660c690db8f30933d27f482f";
    let sk = "76527095233285027606193913571725252597446671752729";
    let pk = public_key_gen(sk.to_string());
    println!("pk_rust: {pk}");
    let cipher = encrypt(pk.clone(), message.to_string(), random.to_string());
    let start1 = Instant::now();
    for i in 1..100{
        let cipher = encrypt(pk.clone(), message.to_string(), random.to_string());
    }
    let end1 = Instant::now();
    println!("加密100次运行时间: {:?}", end1 - start1);
    let start2 = Instant::now();
    for i in 1..100{
        let m = decrypt(sk.to_string(), cipher.clone());
    }
    let end2 = Instant::now();
    println!("解密100次运行时间: {:?}", end2 - start2);
}