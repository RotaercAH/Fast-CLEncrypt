#include <string>
#include <sstream>
#include <iostream>
#include <random>
#include <ctime>
#include <chrono>
#include "../src/bicycl.hpp"
using namespace BICYCL;
extern "C"

// void encrypt(const char* message){
    // RandGen randgen;
    // BIGNUM* message_bn = BN_new();
    // BN_hex2bn(&message_bn, message);
    // BICYCL::Mpz message (message_bn);
    // auto seclevel = SecLevel::_128;
    // auto k = 2;
    // CL_HSMqk C (seclevel, k, seclevel, randgen, false);
     //压缩QFI点值
    // auto c1_compressed = c.c1().compressed_repr();
    // int c1_compressed_bits =  c1_compressed.nbits();
    // std::cout << "c1_compressed_bits: " << c1_compressed_bits << std::endl;
     //
    // QFI c1_compressed_recompressed (c1_compressed, c.c1().discriminant());
// }

const char* encrypt_and_decrypt_test(const char* message){
    RandGen randgen;
    BIGNUM* message_bn = BN_new();
    BN_hex2bn(&message_bn, message);
    auto seclevel = SecLevel::_128;
    auto k = 2;
    CL_HSMqk C (seclevel, k, seclevel, randgen, false);
    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;
    SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);
    BICYCL::Mpz message_mpz (message_bn);
    ClearText m (C, message_mpz);
    CipherText c = C.encrypt(pk, m, randgen);
    ClearText t = C.decrypt (sk, c);
    std::string out_str = t.tostring();
    const char* out_char = out_str.c_str();
    return strdup(out_char);
}
// int main(){
//     const char* message = "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d";
//     const char* out = encrypt_and_decrypt_test(message);
//     std::cout << out << std::endl;
// }

/*
int main(){

    //根据系统时间生成一个随机数种子
    RandGen randgen;
    BICYCL::Mpz seed;
    BIGNUM* range = BN_new();
    BN_hex2bn(&range, "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d");
   
    //
    auto seclevel = SecLevel::_128;
    auto k = 2;
    CL_HSMqk C (seclevel, k, seclevel, randgen, false);
    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;
    SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);
    //加密m
    
    // auto T = std::chrono::system_clock::now();
    // seed = static_cast<unsigned long>(T.time_since_epoch().count());
    // randgen.set_seed(seed);
    // auto start = std::chrono::steady_clock::now();
    BIGNUM* message_bn = BN_new();
    BN_rand_range(message_bn, range);
    BICYCL::Mpz message (message_bn);
    ClearText m (C, message);
    std::cout << "m: " << m << std::endl;
    CipherText c = C.encrypt(pk, m, randgen);
    //获取
    auto c1_disc =  c.c1().discriminant();
    auto c2_disc =  c.c2().discriminant();
    //将密文压缩编码
    auto c1_compressed =  c.c1().compressed_repr();
    auto c2_compressed =  c.c2().compressed_repr();
    //编码后的密文序列化
    auto c1_ap = c1_compressed.ap;
    auto c1_b0 = c1_compressed.b0;
    auto c1_g = c1_compressed.g;
    //反序列化密文
    //QFICompressedRepresentation c1_rr (c1_ap);
    //解压缩密文
    QFI c1_rebuild (c1_compressed, c1_disc);
    QFI c2_rebuild (c2_compressed, c2_disc);
    CipherText c_re (c1_rebuild, c2_rebuild);
    ClearText t = C.decrypt (sk, c_re);
    std::string t_str =  t.tostring();
    std::cout << "t: " << t << std::endl;
    std::cout << "t_str: " << t_str << std::endl;
    auto end = std::chrono::steady_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "gene random time: " << duration1 << "us" << std::endl;
    //解密获得t 判断是否等于m
    auto start1 = std::chrono::steady_clock::now();
    
    auto end1 = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1).count();
    std::cout << "decrypt time: " << duration2 << "us" << std::endl;
    std::cout << "t: " << t << std::endl;
}
*/