#include <string>
#include <sstream>
#include <iostream>
#include <random>
#include <ctime>
#include <chrono>
#include "../src/bicycl.hpp"
using namespace BICYCL;
extern "C" {
    const char* public_key_gen(const char* sk_str);
    const char* encrypt_and_decrypt_test(const char* message);
    const char* encrypt(const char* pk_str, const char* message);
    const char* decrypt(const char* sk_str, const char* cipher_str);
    const char* add_ciphertexts(const char* pk_str, const char* cipher_str_first, const char* cipher_str_second);
    const char* scal_ciphertexts(const char* pk_str, const char* cipher_str, const char* m_str);
}

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
    Mpz ap(qfi_vec[0]);
    Mpz g(qfi_vec[1]);
    Mpz tp(qfi_vec[2]);
    Mpz b0(qfi_vec[3]);
    bool is_neg = qfi_vec[4] == "true" ? true : false;
    Mpz disc(qfi_vec[5]);
    QFICompressedRepresentation qfi_comp (ap, g, tp, b0, is_neg);
    QFI qfi(qfi_comp, disc);
    return qfi;
}

std::string pk_to_str(BICYCL::CL_HSMqk::PublicKey pk){
    return qfi_to_str(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi_to_str(pk.e_precomp()) + ":" + qfi_to_str(pk.d_precomp()) + ":" + qfi_to_str(pk.de_precomp());
}

CL_HSMqk::PublicKey str_to_pk(std::string pk_str){
    std::vector<std::string> pk_vec = splitString(pk_str, ':');
    QFI elt = str_to_qfi(pk_vec[0]);
    size_t d = stoi(pk_vec[1]);
    size_t e = stoi(pk_vec[2]);
    QFI e_precomp = str_to_qfi(pk_vec[3]);
    QFI d_precomp = str_to_qfi(pk_vec[4]);
    QFI de_precomp = str_to_qfi(pk_vec[5]);
    CL_HSMqk::PublicKey pk(elt, d, e, e_precomp, d_precomp, de_precomp);
    return pk;
}

CL_HSMqk generate_C(){
    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    Mpz M_ ("35082577950394243101771455480308837195086416207422866395986335469645130651403699990459815877628197357603732868565417");
    Mpz exponent_bound_ ("6053567222028239460822845227008");
    size_t d = 52;
    size_t e = 27;
    std::string h_str = "12921288867771414943 1 -2700005060 0 true -982091052466434015324328275334900611819";
    auto e_precomp_str = "5438419558175809081 1 -1511434731 0 false -982091052466434015324328275334900611819";
    auto d_precomp_str =  "5115785705323458981 1 899307131 0 false -982091052466434015324328275334900611819";
    auto de_precomp_str =  "475603144690409619 1 143598731 0 false -982091052466434015324328275334900611819";
    CL_HSMqk C (q_, 3, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}

const char* public_key_gen(const char* sk_str){
    CL_HSMqk C(generate_C());

    BICYCL::Mpz sk_mpz (sk_str);

    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    std::string pk_str = pk_to_str(pk);

    const char* pk_char = pk_str.c_str();
    return strdup(pk_char);
}

const char* encrypt(const char* pk_str, const char* message){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    BIGNUM* message_bn = BN_new();
    BN_hex2bn(&message_bn, message);
    BICYCL::Mpz message_mpz (message_bn);
    BICYCL::CL_HSMqk::ClearText m (C, message_mpz);

    CL_HSMqk::PublicKey pk =  str_to_pk(pk_str);

    BICYCL::CL_HSMqk::CipherText c = C.encrypt(pk, m, randgen);
    std::string cipher_str =  qfi_to_str(c.c1()) + ":" + qfi_to_str(c.c2());

    const char* cipher_char = cipher_str.c_str();
    return strdup(cipher_char);
}

const char* decrypt(const char* sk_str, const char* cipher_str){
    CL_HSMqk C(generate_C());

    BICYCL::Mpz sk_mpz (sk_str);
    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    CL_HSMqk::ClearText m = C.decrypt (sk, c);
    std::string m_str = m.tostring();
    const char* m_char = m_str.c_str();
    return strdup(m_char);

}

const char* add_ciphertexts(const char* pk_str, const char* cipher_str_first, const char* cipher_str_second){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());
    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_first_vec = splitString(cipher_str_first, ':');
    CL_HSMqk::CipherText c_first(str_to_qfi(cipher_first_vec[0]), str_to_qfi(cipher_first_vec[1]));

    std::vector<std::string> cipher_second_vec = splitString(cipher_str_second, ':');
    CL_HSMqk::CipherText c_second(str_to_qfi(cipher_second_vec[0]), str_to_qfi(cipher_second_vec[1]));

    CL_HSMqk::CipherText res =  C.add_ciphertexts(pk, c_first, c_second, randgen);

    std::string res_str =  qfi_to_str(res.c1()) + ":" + qfi_to_str(res.c2());
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* scal_ciphertexts(const char* pk_str, const char* cipher_str, const char* m_str){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());
    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    BIGNUM* message_bn = BN_new();
    BN_hex2bn(&message_bn, m_str);
    BICYCL::Mpz message_mpz (message_bn);
    BICYCL::CL_HSMqk::ClearText m (C, message_mpz);

    CL_HSMqk::CipherText res = C.scal_ciphertexts(pk, c, message_mpz, randgen);

    std::string res_str =  qfi_to_str(res.c1()) + ":" + qfi_to_str(res.c2());
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* encrypt_and_decrypt_test(const char* message){
    RandGen randgen;
    BIGNUM* message_bn = BN_new();

    BN_hex2bn(&message_bn, message);
    Mpz q_ ("327363684155478005108109425111633537273");
    Mpz p_ ("3");
    Mpz fud_ ("1099511627776");
    CL_HSMqk C (q_, 3, p_, fud_, true);

    using PublicKey = typename CL_HSMqk::PublicKey;
    using SecretKey = typename CL_HSMqk::SecretKey;
    using ClearText = typename CL_HSMqk::ClearText;
    using CipherText = typename CL_HSMqk::CipherText;

    const char* sk_char =  "4731285847384423928591964720590";
    BICYCL::Mpz sk_mpz (sk_char);
    SecretKey sk = C.keygen (sk_mpz);
    PublicKey pk = C.keygen (sk);

    std::string pk_str = qfi_to_str(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi_to_str(pk.e_precomp()) + ":" + qfi_to_str(pk.d_precomp()) + ":" + qfi_to_str(pk.de_precomp());
    const char* pk_char = pk_str.c_str();
    std::cout << "pk_char: " << pk_char << std::endl;
    BICYCL::Mpz message_mpz (message_bn);
    ClearText m (C, message_mpz);
    CipherText c = C.encrypt(pk, m, randgen);
    ClearText t = C.decrypt (sk, c);
    std::cout << "t: " << t << std::endl;
    std::string out_str = t.tostring();
    const char* out_char = out_str.c_str();
    return strdup(pk_char);
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
    auto pk =  public_key_gen("3046837242676568429961339102363");
    auto cipher_a = encrypt(pk, "ff");
    auto cipher_b = encrypt(pk, "2");
    auto cipher_add = add_ciphertexts(pk, cipher_a, cipher_b);
    auto cipher_scal = scal_ciphertexts(pk, cipher_b, "3");
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 1000; i++){
       auto m_add = decrypt("3046837242676568429961339102363", cipher_add);
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "gen hsmqk time: " << duration2 << "us" << std::endl;
}

int main(){
    auto pk =  public_key_gen("3046837242676568429961339102363");
    auto cipher_a = encrypt(pk, "ff");
    auto cipher_b = encrypt(pk, "2");
    auto cipher_add = add_ciphertexts(pk, cipher_a, cipher_b);
    auto cipher_scal = scal_ciphertexts(pk, cipher_b, "3");
    auto m_add = decrypt("3046837242676568429961339102363", cipher_add);
    auto m_scal = decrypt("3046837242676568429961339102363", cipher_scal);
    std::cout << "m_add: " << m_add << std::endl;
    std::cout << "m_scal: " << m_scal << std::endl;
    test_run_time();
}