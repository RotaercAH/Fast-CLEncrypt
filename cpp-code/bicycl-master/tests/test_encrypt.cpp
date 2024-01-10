#include <string>
#include <sstream>
#include <iostream>
#include <random>
#include <ctime>
#include <chrono>
#include "../src/bicycl.hpp"
using namespace BICYCL;
extern "C" {
    const char* public_key_gen_cpp(const char* sk_str);
    const char* encrypt_and_decrypt_test_cpp(const char* message);
    const char* encrypt_cpp(const char* pk_str, const char* message);
    const char* decrypt_cpp(const char* sk_str, const char* cipher_str);
    const char* add_ciphertexts_cpp(const char* pk_str, const char* cipher_str_first, const char* cipher_str_second);
    const char* scal_ciphertexts_cpp(const char* pk_str, const char* cipher_str, const char* m_str);
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
    Mpz q_ ("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    Mpz p_ ("7");
    Mpz fud_ ("1099511627776");
    Mpz M_ ("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    Mpz exponent_bound_ ("274943655700254057025659698957876137276094883561472");
    size_t d = 84;
    size_t e = 43;
    std::string h_str = "280670455006317297142780913951782675211 1 7913954878590475691 0 true -810544624472493741338882128645853014709978686568950322396955813427479584310583";
    auto e_precomp_str = "83922144963705800495001663749929770781 2 3422882908567569719 1 true -810544624472493741338882128645853014709978686568950322396955813427479584310583";
    auto d_precomp_str =  "436481443196091627310237084764734615354 1 16256212019937773053 0 false -810544624472493741338882128645853014709978686568950322396955813427479584310583";
    auto de_precomp_str =  "249884983147286955634751169591721864979 1 12935238997215073023 0 true -810544624472493741338882128645853014709978686568950322396955813427479584310583";
    CL_HSMqk C (q_, 1, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}

const char* public_key_gen_cpp(const char* sk_str){
    CL_HSMqk C(generate_C());

    BICYCL::Mpz sk_mpz (sk_str);

    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    std::string pk_str = pk_to_str(pk);

    const char* pk_char = pk_str.c_str();
    return strdup(pk_char);
}

const char* encrypt_cpp(const char* pk_str, const char* message){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    // CL_HSMqk_ZKAoK zk (C, randgen);

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

const char* decrypt_cpp(const char* sk_str, const char* cipher_str){
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

const char* add_ciphertexts_cpp(const char* pk_str, const char* cipher_str_first, const char* cipher_str_second){
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

const char* scal_ciphertexts_cpp(const char* pk_str, const char* cipher_str, const char* m_str){
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

void test_ecc_calculate(){
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *G = EC_GROUP_get0_generator (group);
    EC_POINT *smG = EC_POINT_new(group);
    EC_POINT *T = EC_POINT_new(group);
    EC_POINT *mG = EC_POINT_new(group);
    EC_POINT *zmG = EC_POINT_new(group);
    EC_POINT *e = EC_POINT_new(group);

    BIGNUM* sm_bn = BN_new();
    BN_hex2bn(&sm_bn, "9a8477c3453fe8cc2f521a81e331e13d46c1a9f6ac1a194f57754fc21e8c0ecf");
    BIGNUM* m_bn = BN_new();
    BN_hex2bn(&m_bn, "660c690db");
    BIGNUM* e_bn = BN_new();
    BN_hex2bn(&e_bn, "2dd96d5cdd1b09d1fa08542ce6dea6e5");
    BIGNUM* zm_bn = BN_new();
    BN_mul(zm_bn, e_bn, m_bn, ctx);
    BN_add(zm_bn, zm_bn, sm_bn); //  zm = sm + em
    EC_POINT_mul(group, mG, NULL, G, m_bn, ctx); // mG = m * G

    // prove
    EC_POINT_mul(group, smG, NULL, G, sm_bn, ctx); // T = smG =  sm * G 

    // verify
    EC_POINT_mul(group, T, NULL, G, zm_bn, ctx); // T = zmG =  zm * G = (sm + em) * G

    BIGNUM* neg_one = BN_new();
    BN_one(neg_one);
    BN_set_negative(neg_one, 1);

    EC_POINT* neg_commit = EC_POINT_new(group);
    EC_POINT_mul(group, neg_commit, NULL, mG, neg_one, ctx); // neg_commit = -mG
    EC_POINT_mul(group, neg_commit, NULL, neg_commit, e_bn, ctx); // neg_commit = -emG
    EC_POINT_add(group, T, T, neg_commit, ctx); // T = zm * G - em * G = sm * G

    auto T_str =  EC_POINT_point2hex(group, T, POINT_CONVERSION_COMPRESSED, ctx);
    auto smG_str =  EC_POINT_point2hex(group, smG, POINT_CONVERSION_COMPRESSED, ctx);

    std::cout << "T: " << T_str << std::endl;
    std::cout << "smG: " << smG_str << std::endl;

    char * mG_str  = EC_POINT_point2hex(group, mG, POINT_CONVERSION_COMPRESSED, ctx);
    std::cout << "mG_str: " << mG_str << std::endl;
}

void test_run_time(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    CL_HSMqk C(generate_C());
    CL_HSMqk::SecretKey sk = C.keygen(randgen);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    CL_HSMqk::ClearText m (C, randgen);
    std::cout << "m: " << m << std::endl;
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 1000; i++){
         CL_HSMqk::CipherText c = C.encrypt(pk, m, randgen);
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "zk encrypt time: " << duration2 << "us" << std::endl;
}

int main(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    test_ecc_calculate();
    // auto pk =  public_key_gen_cpp("76527095233285027606193913571725252597446671752729");
    // auto cipher_a = encrypt_cpp(pk, "ff");
    // auto cipher_b = encrypt_cpp(pk, "2");
    // auto cipher_add = add_ciphertexts_cpp(pk, cipher_a, cipher_b);
    // auto cipher_scal = scal_ciphertexts_cpp(pk, cipher_b, "3");
    // auto m_add = decrypt_cpp("76527095233285027606193913571725252597446671752729", cipher_add);
    // auto m_scal = decrypt_cpp("76527095233285027606193913571725252597446671752729", cipher_scal);
    // std::cout << "m_add: " << m_add << std::endl;
    // std::cout << "m_scal: " << m_scal << std::endl;
    CL_HSMqk C(generate_C());
    CL_HSMqk_ZKAoK zk(C, randgen);
    // // test_run_time();
    CL_HSMqk::SecretKey sk = C.keygen(randgen);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    BIGNUM* message = BN_new();
    BN_hex2bn(&message, "660c690db");
    Mpz message_mpz (message);
    CL_HSMqk::ClearText m (C, message_mpz);
    std::cout << "m: " << m << std::endl;
    Mpz r (randgen.random_mpz (C.encrypt_randomness_bound()));
   
    CL_HSMqk::CipherText c =  zk.encrypt(pk, m, r);
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *G = EC_GROUP_get0_generator (group);
    EC_POINT *commit = EC_POINT_new(group);
    BIGNUM* m_bn = BN_new();
    BN_dec2bn(&m_bn, m.tostring().c_str());
    EC_POINT_mul(group, commit, NULL, G, m_bn, ctx);

    auto proof = zk.cl_ecc_proof(pk, c, commit, m, r, randgen);
    auto verify = zk.cl_ecc_verify(pk, c, commit, proof);
    std::cout << "zkp res: " << verify << std::endl;
    // auto proof = zpk.noninteractive_proof(pk, c, m, r, randgen);
    // auto verify = zpk.noninteractive_verify(pk, c, proof);
  
    // const char* sk_char =  "4731285847384423928591964720590";
    // BICYCL::Mpz sk_mpz (sk_char);
    // CL_HSMqk::SecretKey sk = C.keygen (sk_mpz);
    // CL_HSMqk::PublicKey pk = C.keygen (sk);

    // CL_HSMqk_ZKAoK zk (C, randgen);

    // BIGNUM* message_bn = BN_new();
    // BN_hex2bn(&message_bn, "660c690db8f30933d27f482f2e80ed5092998410882163f3b9dae1c2125ede1d");
    // BICYCL::Mpz message (message_bn);
    // CL_HSMqk::ClearText m (C, message);

    // Mpz r ("3971145550799047016767358266139");
    // CL_HSMqk::CipherText c = zk.encrypt (pk, m, r);
    // std::cout << "c1: " << c.c1() << std::endl;
    // std::cout << "c2: " << c.c2() << std::endl;
    // CL_HSMqk_ZKAoK::Proof p = zk.noninteractive_proof (pk, c, m, r, randgen);

    // auto verify = zk.noninteractive_verify (pk, c, p);
    // std::cout << "verify: " << verify << std::endl;
}