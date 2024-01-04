#include <string>
#include <sstream>
#include <iostream>
#include <random>
#include <ctime>
#include <chrono>
#include "../src/bicycl.hpp"
using namespace BICYCL;
extern "C"

std::vector<std::string> splitString(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        tokens.push_back(item);
    }
    
    return tokens;
}

std::string qfi_to_str(QFI qfi){
    auto qfi_comp = qfi.compressed_repr();
    const std::string is_neg = (qfi_comp.is_neg) ? "true" : "false";
    auto out = qfi_comp.ap.tostring() + " " + qfi_comp.g.tostring() + " " + qfi_comp.tp.tostring() + " " + qfi_comp.b0.tostring() + " " + is_neg + " " + qfi.discriminant().tostring();
    return out;
}

QFI str_to_qfi(std::string qfi_str){
    std::vector<std::string> qfi_vec = splitString(qfi_str, ' ');
    BICYCL::Mpz ap(qfi_vec[0]);
    BICYCL::Mpz g(qfi_vec[1]);
    BICYCL::Mpz tp(qfi_vec[2]);
    BICYCL::Mpz b0(qfi_vec[3]);
    bool is_neg = qfi_vec[4] == "true" ? true : false;
    BICYCL::Mpz disc(qfi_vec[5]);
    QFICompressedRepresentation qfi_comp (ap, g, tp, b0, is_neg);
    QFI qfi(qfi_comp, disc);
    return qfi;
}

std::string pk_to_str(BICYCL::CL_HSMqk::PublicKey pk){
    auto out = qfi_to_str(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi_to_str(pk.e_precomp()) + ":" + qfi_to_str(pk.d_precomp()) + ":" + qfi_to_str(pk.de_precomp());
    std::cout << "pk_str" << out << std::endl;
    return out;
}

BICYCL::CL_HSMqk::PublicKey str_to_pk(std::string pk_str){
    std::vector<std::string> pk_vec = splitString(pk_str, ':');
    QFI elt = str_to_qfi(pk_vec[0]);
    size_t d = stoi(pk_vec[1]);
    size_t e = stoi(pk_vec[2]);
    QFI e_precomp = str_to_qfi(pk_vec[3]);
    QFI d_precomp = str_to_qfi(pk_vec[4]);
    QFI de_precomp = str_to_qfi(pk_vec[5]);
    BICYCL::CL_HSMqk::PublicKey pk(elt, d, e, e_precomp, d_precomp, de_precomp);
    std::cout << "pk_after: " << pk << std::endl;
}

const char* public_key_gen(const char* sk_str){
    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    CL_HSMqk C (q_, 3, p_, fud_, true);

    BICYCL::Mpz sk_mpz (sk_str);

    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    auto pk_str = qfi_to_str(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi_to_str(pk.e_precomp()) + ":" + qfi_to_str(pk.d_precomp()) + ":" + qfi_to_str(pk.de_precomp());
    const char* pk_char = pk_str.c_str();
    return strdup(pk_char);
}

const char* encrypt(const char* pk_str, const char* message){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;

    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    CL_HSMqk C (q_, 3, p_, fud_, true);

    BICYCL::Mpz message_mpz (message);
    ClearText m (C, message_mpz);

    std::vector<std::string> pk_vec = splitString(pk_str, ':');
    QFI elt = str_to_qfi(pk_vec[0]);
    size_t d = stoi(pk_vec[1]);
    size_t e = stoi(pk_vec[2]);
    QFI e_precomp = str_to_qfi(pk_vec[3]);
    QFI d_precomp = str_to_qfi(pk_vec[4]);
    QFI de_precomp = str_to_qfi(pk_vec[5]);
    BICYCL::CL_HSMqk::PublicKey pk(elt, d, e, e_precomp, d_precomp, de_precomp);

    CipherText c = C.encrypt(pk, m, randgen);

    std::string cipher_str =  qfi_to_str(c.c1()) + ":" + qfi_to_str(c.c2());

    const char* cipher_char = cipher_str.c_str();
    return strdup(cipher_char);
}

const char* decrypt(const char* sk_str, const char* cipher_str){
    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    CL_HSMqk C (q_, 3, p_, fud_, true);

    BICYCL::Mpz sk_mpz (sk_str);
    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    CL_HSMqk::ClearText m = C.decrypt (sk, c);
    std::string m_str = m.tostring();
    const char* m_char = m_str.c_str();
    return strdup(m_char);

}

const char* encrypt_and_decrypt_test(const char* message){
    RandGen randgen;
    auto seclevel = SecLevel::_128;
    auto k = 3;
    CL_HSMqk C (seclevel, k, seclevel, randgen, true);
    auto randmpz = randgen.random_mpz(C.encrypt_randomness_bound());
    std::cout << "encrypt_randomness_bound: " << C.encrypt_randomness_bound() << std::endl;
    std::cout << "mpz: " << randmpz << std::endl;
    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    CL_HSMqk C2 (q_, 3, p_, fud_, true);
    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;
    SecretKey sk = C.keygen (randgen);
    std::cout << "sk: " << sk << std::endl;
    PublicKey pk = C.keygen (sk);
    auto elt = pk.elt();
    std::cout << "elt: " << elt << std::endl;
    std::cout << "pk: " << pk << std::endl;
    BICYCL::Mpz message_mpz (message);
    ClearText m (C, message_mpz);
    // ClearText m (C, message);
    std::cout << "m: " << m << std::endl;
    CipherText c = C.encrypt(pk, m, randgen);
    std::cout << "c: " << c.c1() << std::endl;
    std::cout << "c: " << c.c2() << std::endl;
    ClearText t = C2.decrypt (sk, c);
    std::cout << "t: " << t << std::endl;
    std::string out_str = t.tostring();
    const char* out_char = out_str.c_str();
    return strdup(out_char);
}

void test_encrypt_with_r(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    BIGNUM* range = BN_new();
    BN_hex2bn(&range, "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d");
    auto seclevel = SecLevel::_128;
    auto k = 3;       
    CL_HSMqk C (seclevel, k, seclevel, randgen);
    std::cout << C.fud_factor() << std::endl;
    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;
    SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);
    BIGNUM* message_bn = BN_new();
    BN_rand_range(message_bn, range);
    BICYCL::Mpz message (message_bn);
    ClearText m (C, message);
    auto random = C.q();
    CipherText c = C.encrypt(pk, m, random);
    ClearText t = C.decrypt (sk, c);
}

void test_run_time(){
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 100; i++){
        test_encrypt_with_r();
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "gen hsmqk time: " << duration2 << "us" << std::endl;
}

int main(){
    BIGNUM* message_bn = BN_new();
    BN_hex2bn(&message_bn, "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d");
    const char* message =  BN_bn2dec(message_bn);
    std::cout << "message: " << message << std::endl;
    const char* sk =  "4731285847384423928591964720590";
    const char* pk = public_key_gen(sk);
    const char* cipher = encrypt(pk, message);
    const char* m = decrypt(sk, cipher);
    std::cout << "m " << m << std::endl;
}

/*
int main(){

    //根据系统时间生成一个随机数种子
    RandGen randgen;
    BICYCL::Mpz seed;
    BIGNUM* range = BN_new();
    BN_hex2bn(&range, "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d");
    //
    auto seclevel = SecLevel::_128;
    auto k = 3;
    CL_HSMqk C (seclevel, k, seclevel, randgen, true);
    // std::cout << "q: " << C.q() << std::endl;
    // std::cout << "p: " << C.p() << std::endl;
    // std::cout << "fud: " << C.fud_factor() << std::endl;

    // Mpz q_ ("327363684155478005108109425111633537273");
    // Mpz p_ ("3");
    // Mpz fud_ ("1099511627776");
    // CL_HSMqk C_re (q_, 3, p_, fud_, true);
    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;
    const char* sk_char =  "4731285847384423928591964720590";
    BICYCL::Mpz sk_mpz (sk_char);
    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);

    // SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);
    std::cout << "sk: " << sk << std::endl;
    //序列化公钥
    auto pk_str = qfi_to_str(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi_to_str(pk.e_precomp()) + ":" + qfi_to_str(pk.d_precomp()) + ":" + qfi_to_str(pk.de_precomp());
    // std::string pk_str = pk_to_str(pk);
    ////反序列化公钥
    // PublicKey pk_re = str_to_pk(pk_str);
    // std::cout << "pk_after_2: " << pk_re << std::endl;
    std::vector<std::string> pk_vec = splitString(pk_str, ':');
    QFI elt = str_to_qfi(pk_vec[0]);
    size_t d = stoi(pk_vec[1]);
    size_t e = stoi(pk_vec[2]);
    QFI e_precomp = str_to_qfi(pk_vec[3]);
    QFI d_precomp = str_to_qfi(pk_vec[4]);
    QFI de_precomp = str_to_qfi(pk_vec[5]);
    BICYCL::CL_HSMqk::PublicKey pk_re(elt, d, e, e_precomp, d_precomp, de_precomp);
    //加密m
    BIGNUM* message_bn = BN_new();
    BN_rand_range(message_bn, range);
    BICYCL::Mpz message (message_bn);
    ClearText m (C, message);
    std::cout << "m: " << m << std::endl;
    CipherText c = C.encrypt(pk_re, m, randgen);
    std::string c1 = qfi_to_str(c.c1());
    std::string c2 = qfi_to_str(c.c2());
    CipherText c_re(str_to_qfi(c1), str_to_qfi(c2));
    ClearText t = C.decrypt (sk, c_re);
    std::cout << "t: " << t << std::endl;
}
*/