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
    const char* encrypt_cpp(const char* pk_str, const char* message, const char* random);
    const char* decrypt_cpp(const char* sk_str, const char* cipher_str);
    const char* add_ciphertexts_cpp(const char* pk_str, const char* cipher_str_first, const char* cipher_str_second);
    const char* scal_ciphertexts_cpp(const char* pk_str, const char* cipher_str, const char* m_str);
    const char* cl_ecc_prove_cpp(const char* pk_str, const char* cipher_str, const char* commit_str, const char* m_str, const char* r_str);
    const char* cl_ecc_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* commit_str);
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

// CL_HSMqk_ZKAoK generate_zk(){
//     CL_HSMqk C(generate_C());
//     Mpz random ("159084427090018101437667879809210211166256988396131");
//     CL_HSMqk_ZKAoK zk(C, 128, random);
//     return zk;
// }

const char* public_key_gen_cpp(const char* sk_str){
    CL_HSMqk C = generate_C();
   
    BICYCL::Mpz sk_mpz (sk_str);

    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    std::string pk_str = pk_to_str(pk);

    const char* pk_char = pk_str.c_str();
    return strdup(pk_char);
}

const char* encrypt_cpp(const char* pk_str, const char* message, const char* random){
    CL_HSMqk C(generate_C());

    CL_HSMqk::ClearText  m (C, Mpz (message));

    CL_HSMqk::PublicKey pk =  str_to_pk(pk_str);

    BICYCL::CL_HSMqk::CipherText c = C.encrypt(pk, m, Mpz (random));
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

    CL_HSMqk::CipherText res = C.scal_ciphertexts(pk, c, Mpz(m_str), randgen);

    std::string res_str =  qfi_to_str(res.c1()) + ":" + qfi_to_str(res.c2());
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* cl_ecc_prove_cpp(const char* pk_str, const char* cipher_str, const char* commit_str, const char* m_str, const char* r_str){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *commit = EC_POINT_hex2point(group, commit_str, NULL, ctx);
    
    auto commit_str_ =  EC_POINT_point2hex(group, commit, POINT_CONVERSION_COMPRESSED, ctx);
    std::cout << "commit_proof_str: " << commit_str_ << std::endl;

    BICYCL::CL_HSMqk::ClearText m (C, Mpz (m_str));

    auto proof =  C.cl_ecc_proof(pk, c, commit, m, Mpz(r_str), randgen);
    std::string proof_str = proof.toString();
    const char* proof_char = proof_str.c_str();
    return strdup(proof_char);
}

const char* cl_ecc_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* commit_str){

    std::vector<std::string> proof_vec = splitString(proof_str, ' ');
    Mpz zm(proof_vec[0]);
    Mpz zr(proof_vec[1]);
    Mpz e(proof_vec[2]);
    CL_HSMqk::CL_ECC_Proof proof(zm, zr, e);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *commit = EC_POINT_hex2point(group, commit_str, NULL, ctx);

    auto commit_str_ =  EC_POINT_point2hex(group, commit, POINT_CONVERSION_COMPRESSED, ctx);
    std::cout << "commit_verify_str: " << commit_str_ << std::endl;

    auto verify = C.cl_ecc_verify(pk, c, commit, proof);
    const std::string res = (verify) ? "true" : "false";

    const char* res_char = res.c_str();
    return strdup(res_char);
}

void test_run_time(){
    // RandGen randgen;
    // BICYCL::Mpz seed;
    // auto T = std::chrono::system_clock::now();
    // seed = static_cast<unsigned long>(T.time_since_epoch().count());
    // randgen.set_seed(seed);
    // CL_HSMqk C(generate_C());
    // CL_HSMqk::SecretKey sk = C.keygen(randgen);
    // CL_HSMqk::PublicKey pk = C.keygen(sk);
    // CL_HSMqk::ClearText m (C, randgen);
    // std::cout << "m: " << m << std::endl;
    auto start = std::chrono::steady_clock::now();
    auto pk =  public_key_gen_cpp("76527095233285027606193913571725252597446671752729");
    Mpz random ("159084427090018101437667879809210211166256988396131");
    CL_HSMqk C(generate_C());
    for(int i = 0; i < 1000; i++){
        encrypt_cpp(pk, random.tostring().c_str(),  random.tostring().c_str());
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "encrypt time: " << duration2 << "us" << std::endl;
}

int main(){
    test_run_time();

    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    auto pk =  public_key_gen_cpp("76527095233285027606193913571725252597446671752729");

    CL_HSMqk C(generate_C());
    Mpz random ("159084427090018101437667879809210211166256988396131");
    CL_HSMqk_ZKAoK zk(C, 128, random);

    Mpz r_a(randgen.random_mpz (zk.encrypt_randomness_bound()));
    Mpz r_b(randgen.random_mpz (zk.encrypt_randomness_bound()));

    auto cipher_a = encrypt_cpp(pk, "123", r_a.tostring().c_str());
    auto cipher_b = encrypt_cpp(pk, "2",  r_b.tostring().c_str());
    auto cipher_add = add_ciphertexts_cpp(pk, cipher_a, cipher_b);
    auto cipher_scal = scal_ciphertexts_cpp(pk, cipher_b, "3");
    auto m_add = decrypt_cpp("76527095233285027606193913571725252597446671752729", cipher_add);
    auto m_scal = decrypt_cpp("76527095233285027606193913571725252597446671752729", cipher_scal);

    std::cout << "m_add: " << m_add << std::endl;
    std::cout << "m_scal: " << m_scal << std::endl;

    BIGNUM* m_bn = BN_new();
    BN_dec2bn(&m_bn, "123");
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    auto order = EC_GROUP_get0_order(group);
    std::cout << "order: " << order << std::endl;
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    auto g_str = EC_POINT_point2hex(group, G, POINT_CONVERSION_UNCOMPRESSED, ctx);
    std::cout << "g_str: " << g_str << std::endl;
    EC_POINT *commit = EC_POINT_new(group);
    EC_POINT_mul(group, commit, NULL, G, m_bn, ctx);
    auto commit_str =  EC_POINT_point2hex(group, commit, POINT_CONVERSION_COMPRESSED, ctx);
    std::cout << "commit_str: " << commit_str << std::endl;
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 1000; i++){
        auto proof_test = cl_ecc_prove_cpp(pk, cipher_a, commit_str, "123", r_a.tostring().c_str());
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "proof time: " << duration2 << "us" << std::endl;
    auto proof = cl_ecc_prove_cpp(pk, cipher_a, commit_str, "123", r_a.tostring().c_str());
    std::cout << "proof: " << proof << std::endl;
    auto verify = cl_ecc_verify_cpp(proof, pk, cipher_a, commit_str);
    std::cout << "verify: " << verify << std::endl;
}