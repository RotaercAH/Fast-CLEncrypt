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
    const char* add_ciphertexts_cpp(const char* cipher_str_first, const char* cipher_str_second);
    const char* scal_ciphertexts_cpp(const char* cipher_str, const char* m_str);
    const char* encrypt_prove_cpp(const char* pk_str, const char* cipher_str, const char* m_str, const char* r_str);
    const char* encrypt_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str);
    const char* cl_ecc_prove_cpp(const char* pk_str, const char* cipher_str, const char* commit_str, const char* m_str, const char* r_str);
    const char* cl_ecc_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* commit_str);
    const char* cl_cl_prove_cpp(const char* pk1_str, const char* pk2_str, const char* cipher1_str, const char* cipher2_str, const char* m_str, const char* r1_str, const char* r2_str);
    const char* cl_cl_verify_cpp(const char* proof_str, const char* pk1_str, const char* pk2_str, const char* cipher1_str, const char* cipher2_str);
    const char* qfi_add_cpp(const char* qfi1_str, char* qfi2_str);
    const char* qfi_mul_cpp(const char* qfi_str, char* mpz_str);
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
    Mpz q_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz p_ ("7");
    Mpz fud_ ("680564733841876926926749214863536422912");
    Mpz M_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz exponent_bound_ ("321756228303888102507804458520349453098375605088512731522548622988798752456704");
    size_t d = 129;
    size_t e = 65;
    std::string h_str = "144981785181062899352360633526556264162 1 -3094606589199551713 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto e_precomp_str = "387981918959330339119301998504042175116 1 7151058272209265361 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto d_precomp_str =  "326980751728661465979182082279774210476 1 1801040507300303337 0 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto de_precomp_str =  "123153628275337705408626747040696554382 1 2516637161612544649 0 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    CL_HSMqk C (q_, 1, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}
/*
CL_HSMqk generate_C(){
    Mpz q_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz p_ ("7");
    Mpz fud_ ("85070591730234615865843651857942052864");
    // CL_HSMqk C(q_, 1, p_, fud_, true);
    // std::cout << "M: " << C.M() << std::endl;
    // std::cout << "exponent_bound" << C.secretkey_bound() <<std::endl;
    // std::cout << "d" << C.d() <<std::endl;
    // std::cout << "e" << C.e() <<std::endl;
    // std::cout << "h" << qfi_to_str(C.h()) <<std::endl;
    // std::cout << "e_pre" << qfi_to_str(C.h_e_precomp()) <<std::endl;
    // std::cout << "d_pre" << qfi_to_str(C.h_d_precomp()) <<std::endl;
    // std::cout << "de_pre" << qfi_to_str(C.h_de_precomp()) <<std::endl;
    Mpz M_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz exponent_bound_ ("40219528537986012813475557315043681637296950636064091440318577873599844057088");
    size_t d = 128;
    size_t e = 65;
    std::string h_str = "144981785181062899352360633526556264162 1 -3094606589199551713 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto e_precomp_str = "387981918959330339119301998504042175116 1 7151058272209265361 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto d_precomp_str =  "3201118217763513943109252430225497086 115 89241095639766715 29 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto de_precomp_str =  "47889464931934708780281035133841485103 4 -885674612390537642 3 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    CL_HSMqk C (q_, 1, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}
*/
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

const char* add_ciphertexts_cpp(const char* cipher_str_first, const char* cipher_str_second){
    CL_HSMqk C(generate_C());

    std::vector<std::string> cipher_first_vec = splitString(cipher_str_first, ':');
    CL_HSMqk::CipherText c_first(str_to_qfi(cipher_first_vec[0]), str_to_qfi(cipher_first_vec[1]));

    std::vector<std::string> cipher_second_vec = splitString(cipher_str_second, ':');
    CL_HSMqk::CipherText c_second(str_to_qfi(cipher_second_vec[0]), str_to_qfi(cipher_second_vec[1]));

    CL_HSMqk::CipherText res =  C.add_ciphertexts(c_first, c_second);

    std::string res_str =  qfi_to_str(res.c1()) + ":" + qfi_to_str(res.c2());
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* scal_ciphertexts_cpp(const char* cipher_str, const char* m_str){
    CL_HSMqk C(generate_C());

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    CL_HSMqk::CipherText res = C.scal_ciphertexts(c, Mpz(m_str));

    std::string res_str =  qfi_to_str(res.c1()) + ":" + qfi_to_str(res.c2());
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* sk_power_of_c1_cpp(const char* c1_str, const char* sk_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.Cl_G().nupow (res, str_to_qfi(c1_str), Mpz (sk_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* multi_decrypt_cpp(const char* c1_str, const char* c2_str){
    CL_HSMqk C(generate_C());
    QFI fm = str_to_qfi(c1_str);

    if (C.compact_variant())
    C.from_Cl_DeltaK_to_Cl_Delta (fm);

    C.Cl_Delta().nucompinv (fm, str_to_qfi(c2_str), fm); /* c2/c1^sk */

    Mpz m = C.dlog_in_F(fm);
    std::string m_str = m.tostring();
    const char* m_char = m_str.c_str();
    return strdup(m_char);
}

const char* get_c1(const char* cipher_str){
    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    auto c1_str = cipher_vec[0];
    const char* c1_char = c1_str.c_str();
    return strdup(c1_char);
}

const char* get_c2(const char* cipher_str){
    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    auto c2_str = cipher_vec[1];
    const char* c2_char = c2_str.c_str();
    return strdup(c2_char);
}

const char* add_c1(const char* c1_1_str, const char* c1_2_str){
    QFI res, order, c1_1;
    CL_HSMqk C(generate_C());
    // C.power_of_h (order, Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    // C.Cl_G().nucompinv (c1_1, str_to_qfi(c1_1_str), order);
    C.Cl_G().nucomp (res, str_to_qfi(c1_1_str), str_to_qfi(c1_2_str));
    res.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK());
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* encrypt_prove_cpp(const char* pk_str, const char* cipher_str, const char* m_str, const char* r_str){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    BICYCL::CL_HSMqk::ClearText m (C, Mpz (m_str));

    auto proof =  C.encrypt_proof(pk, c, m, Mpz(r_str), randgen);
    std::string proof_str = proof.encrypt_toString();
    const char* proof_char = proof_str.c_str();
    return strdup(proof_char);
}

const char* encrypt_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str){

    std::vector<std::string> proof_vec = splitString(proof_str, ' ');
    Mpz zm(proof_vec[0]);
    Mpz zr(proof_vec[1]);
    Mpz e(proof_vec[2]);
    CL_HSMqk::Encrypt_Proof proof(zm, zr, e);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    auto verify = C.encrypt_verify(pk, c, proof);
    const std::string res = (verify) ? "true" : "false";

    const char* res_char = res.c_str();
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

    BICYCL::CL_HSMqk::ClearText m (C, Mpz (m_str));

    auto proof =  C.cl_ecc_proof(pk, c, commit, m, Mpz(r_str), randgen);
    std::string proof_str = proof.cl_ecc_toString();
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

    auto verify = C.cl_ecc_verify(pk, c, commit, proof);
    const std::string res = (verify) ? "true" : "false";

    const char* res_char = res.c_str();
    return strdup(res_char);
}

const char* cl_cl_prove_cpp(const char* pk1_str, const char* pk2_str, const char* cipher1_str, const char* cipher2_str, const char* m_str, const char* r1_str, const char* r2_str){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk1 = str_to_pk(pk1_str);
    CL_HSMqk::PublicKey pk2 = str_to_pk(pk2_str);

    std::vector<std::string> cipher1_vec = splitString(cipher1_str, ':');
    CL_HSMqk::CipherText c1(str_to_qfi(cipher1_vec[0]), str_to_qfi(cipher1_vec[1]));
    std::vector<std::string> cipher2_vec = splitString(cipher2_str, ':');
    CL_HSMqk::CipherText c2(str_to_qfi(cipher2_vec[0]), str_to_qfi(cipher2_vec[1]));

    BICYCL::CL_HSMqk::ClearText m (C, Mpz (m_str));

    auto proof =  C.cl_cl_proof(pk1, pk2, c1, c2, m, Mpz(r1_str), Mpz(r2_str), randgen);
    std::string proof_str = proof.cl_cl_toString();
    const char* proof_char = proof_str.c_str();
    return strdup(proof_char);
}

const char* cl_cl_verify_cpp(const char* proof_str, const char* pk1_str, const char* pk2_str, const char* cipher1_str, const char* cipher2_str){

    std::vector<std::string> proof_vec = splitString(proof_str, ' ');
    Mpz zm(proof_vec[0]);
    Mpz zr1(proof_vec[1]);
    Mpz zr2(proof_vec[2]);
    Mpz e(proof_vec[3]);
    CL_HSMqk::CL_CL_Proof proof(zm, zr1, zr2, e);

    CL_HSMqk C(generate_C());

    CL_HSMqk::PublicKey pk1 = str_to_pk(pk1_str);
    CL_HSMqk::PublicKey pk2 = str_to_pk(pk2_str);

    std::vector<std::string> cipher1_vec = splitString(cipher1_str, ':');
    CL_HSMqk::CipherText c1(str_to_qfi(cipher1_vec[0]), str_to_qfi(cipher1_vec[1]));
    std::vector<std::string> cipher2_vec = splitString(cipher2_str, ':');
    CL_HSMqk::CipherText c2(str_to_qfi(cipher2_vec[0]), str_to_qfi(cipher2_vec[1]));

    auto verify = C.cl_cl_verify(pk1, pk2, c1, c2, proof);
    const std::string res = (verify) ? "true" : "false";

    const char* res_char = res.c_str();
    return strdup(res_char);
}

const char* qfi_add_cpp(const char* qfi1_str, char* qfi2_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.Cl_G().nucomp (res, str_to_qfi(qfi1_str), str_to_qfi(qfi2_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* qfi_mul_cpp(const char* qfi_str, char* mpz_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.Cl_G().nupow (res, str_to_qfi(qfi_str), Mpz(mpz_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
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

void test_mpz_vss(){
    Mpz sk_mpz("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    Mpz m ("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    Mpz r; 
    Mpz::mul(r, sk_mpz, m);
    std::cout << "mpz mul: " << r << std::endl;
}

void test_vss(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    CL_HSMqk C(generate_C());

    Mpz sk_mpz("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    Mpz m ("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));

    QFI c1, c2;
    //加密m1
    C.power_of_h (c1, r); /* c1 = h^r */
    QFI fm = C.power_of_f (m); /* fm = [q^2, q, ...]^m */
    pk.exponentiation (C, c1, r); /* pk^r */

    if (C.compact_variant())
    C.from_Cl_DeltaK_to_Cl_Delta (c1);
    C.Cl_Delta().nucomp (c2, c2, fm); /* c2 = f^m*pk^r */

    QFI c1_1, c1_2, c1_add;
    //计算私钥
    Mpz sk1("2");
    Mpz l1("72165701049888658392478773995579939896618539406973043838284094293657329860363");
    Mpz sk2("115792089237316195423570985008687907852837564279074904382605163141518161494336");
    Mpz l2("72282659822282921445424486007020523888626415329828812038172225289818776266188");
    // c1 = h^（r * sk1 * l1）
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 10000; i++){
         C.Cl_G().nupow (c1_1, c1, sk1); 
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "cl_power time: " << duration2 << "us" << std::endl;
    start = std::chrono::steady_clock::now();
    for(int i = 0; i < 10000; i++){
        C.Cl_G().nucomp (c1_add, c1_1, c1_2);
    }
    end = std::chrono::steady_clock::now();
    duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "cl_add_precalculate time: " << duration2 << "us" << std::endl;
    // C.Cl_G().nupow (c1_1, c1, sk1); 
    C.Cl_G().nupow (c1_1, c1_1, l1); 
    // c2 = h^（r * sk2 * l2）
    C.Cl_G().nupow (c1_2, c1, sk2);
    C.Cl_G().nupow (c1_2, c1_2, l2); 
    // c1_add = h ^ r (sk1 * l1 + sk2 * l2）
    C.Cl_G().nucomp (c1_add, c1_1, c1_2);

    //
}

void add_test(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    Mpz m1 ("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    Mpz m2 ("70795547422516615862889718024772333991937014393068567817406786413659743186496");
    Mpz sk_mpz(randgen.random_mpz (C.encrypt_randomness_bound()));
    CL_HSMqk::SecretKey sk = C.keygen(sk_mpz);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    QFI c1_1, c1_2, c2_1, c2_2, c1_add, c2_add;

    //加密m1
    C.power_of_h (c1_1, r); /* c1 = h^r */
    std::cout << "c1_1: " << qfi_to_str(c1_1) << std::endl;
    QFI fm1 = C.power_of_f (m1); /* fm = [q^2, q, ...]^m */
    pk.exponentiation (C, c1_2, r); /* pk^r */
    std::cout << "pk^r before trans: " << qfi_to_str(c1_2) << std::endl;
    if (C.compact_variant())
    C.from_Cl_DeltaK_to_Cl_Delta (c1_2);
    std::cout << "pk^r after trans: " << qfi_to_str(c1_2) << std::endl;
    C.Cl_Delta().nucomp (c1_2, c1_2, fm1); /* c2 = f^m*pk^r */
    std::cout << "c1_2: " << qfi_to_str(c1_2) << std::endl;
    //加密m2
    C.power_of_h (c2_1, r); /* c1 = h^r */
    QFI fm2 = C.power_of_f (m2); /* fm = [q^2, q, ...]^m */
    pk.exponentiation (C, c2_2, r); /* pk^r */

    if (C.compact_variant())
    C.from_Cl_DeltaK_to_Cl_Delta (c2_2);
    C.Cl_Delta().nucomp (c2_2, c2_2, fm2); /* c2 = f^m*pk^r */

    //同态加法
    C.Cl_G().nucomp (c1_add, c1_1, c2_1);
    C.Cl_Delta().nucomp (c2_add, c1_2, c2_2);

    //解密
    C.Cl_G().nupow (c1_add, c1_add, sk);
    QFI fm = c1_add;
    // if (C.compact_variant())
    // {
        C.from_Cl_DeltaK_to_Cl_Delta (fm);
    // }
   
    C.Cl_Delta().nucompinv (fm, c2_add, fm); /* c2/c1^sk */

    Mpz m = C.dlog_in_F(fm);
    std::cout << "m: " << m << std::endl;
}

void multi_test(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());

    // order 40219528537986012813475557315043681637296950636064091440318577873599844057088
    auto sk1_test = "72048742277494395339533061984139355904610663484117275638395963297495883454538";
    Mpz sk1 ("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    sk1.mod(sk1, sk1, C.encrypt_randomness_bound());
    // 31829213739508382526057504669095674267313712848053184198077385423896039397450
    std::cout << "sk1 in test: " << sk1 << std::endl;

    auto sk2_test = "70795547422516615862889718024772333991937014393068567817406786413659743186496";
    Mpz sk2 ("70795547422516615862889718024772333991937014393068567817406786413659743186496");
    Mpz::mod(sk2, sk2, C.encrypt_randomness_bound());
    std::cout << "sk2 in test: " << sk2 << std::endl;
    // 30576018884530603049414160709728652354640063757004476377088208540059899129408
    Mpz total;
    Mpz::add(total, sk1, sk2);
    Mpz::mod(total, total, C.encrypt_randomness_bound());
    // 22185704086052972761996108063780644984656825968993569134847016090356094469770
    std::cout << "total in test: " << total << std::endl;
    auto sk_total = "27052200462694815778851795000223782043710113598110939073197586569637465146697";
    Mpz sk_add ("22185704086052972761996108063780644984656825968993569134847016090356094469770");
    sk_add.mod(sk_add, sk_add, C.encrypt_randomness_bound());
    std::cout << "sk_add in test: " << sk_add << std::endl;

    auto pk_test = public_key_gen_cpp("27052200462694815778851795000223782043710113598110939073197586569637465146697");
    Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    auto cipher_str = encrypt_cpp(pk_test, "123", r.tostring().c_str());
    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    auto c1 = str_to_qfi(cipher_vec[0]);
    auto c2 = str_to_qfi(cipher_vec[1]);

    QFI c1_pow_sk, c1_pow_sk_, c1_1_pow_sk, c1_2_pow_sk, order;
    C.Cl_G().nupow (c1_pow_sk, c1, Mpz (sk_total));
    std::cout << "c1_pow_sk in test: " << c1_pow_sk << std::endl;
    std::cout << "c1_pow_sk in test: " << qfi_to_str(c1_pow_sk) << std::endl;
    //利用两个私钥计算
    C.Cl_G().nupow (c1_1_pow_sk, c1, sk1);
    C.Cl_G().nupow (c1_2_pow_sk, c1, sk2);
    C.Cl_G().nupow (order, c1, C.encrypt_randomness_bound());
    C.Cl_G().nucomp (c1_pow_sk_, c1_1_pow_sk, c1_2_pow_sk);
    C.Cl_G().nucompinv(c1_pow_sk_, c1_pow_sk_, order);
    // c1_pow_sk.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK(), true);
    // c1_pow_sk_.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK(), true);
    std::cout << "c1_pow_sk in test: " << c1_pow_sk_ << std::endl;
    std::cout << "c1_pow_sk_ in test: " << qfi_to_str(c1_pow_sk_) << std::endl;

    QFI fm = c1_pow_sk;
    QFI fm_ = c1_pow_sk_;

    if (C.compact_variant())
    {
        C.from_Cl_DeltaK_to_Cl_Delta (fm);
        C.from_Cl_DeltaK_to_Cl_Delta (fm_);
    }
   
    C.Cl_Delta().nucompinv (fm, c2, fm); /* c2/c1^sk */
    C.Cl_Delta().nucompinv (fm_, c2, fm_); /* c2/c1^sk */

    std::cout << "fm in test: " << fm << std::endl;
    std::cout << "fm in test in test: " << qfi_to_str(fm) << std::endl;
    std::cout << "fm_ in test: " << fm_ << std::endl;
    std::cout << "fm in test_ in test: " << qfi_to_str(fm_) << std::endl;

    Mpz m = C.dlog_in_F(fm);
    Mpz m_ = C.dlog_in_F(fm_);

    std::cout << "m in test: " << m << std::endl;
}

void test_encrypt_and_decrypt(){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C(generate_C());
    CL_HSMqk::SecretKey sk = C.keygen(randgen);
    CL_HSMqk::PublicKey pk = C.keygen(sk);
    CL_HSMqk::ClearText m (C, Mpz("3"));
    Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    CL_HSMqk::CipherText c = C.encrypt(pk, m, r);
    std::cout <<  "m: " << C.decrypt(sk, c) << std::endl;
}

int main(){
    // multi_test();
    // test_run_time();
    // test_encrypt_and_decrypt();
    // add_test()
    // test_vss();
    test_mpz_vss();
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    CL_HSMqk C(generate_C());
    CL_HSMqk::SecretKey sk1 = C.keygen(randgen);
    CL_HSMqk::PublicKey pk1 = C.keygen(sk1);
    CL_HSMqk::SecretKey sk2 = C.keygen(randgen);
    CL_HSMqk::PublicKey pk2 = C.keygen(sk2);
    CL_HSMqk::ClearText m (C, Mpz("3"));
    Mpz r1(randgen.random_mpz (C.encrypt_randomness_bound()));
    Mpz r2(randgen.random_mpz (C.encrypt_randomness_bound()));
    CL_HSMqk::CipherText c1 = C.encrypt(pk1, m, r1);
    // CL_HSMqk::CipherText c2 = C.encrypt(pk2, m_wrong, r2);
    // auto cl_cl_proof = C.cl_cl_proof(pk1, pk2, c1, c2, m, r1, r2, randgen);
    // auto verify_res =  C.cl_cl_verify(pk1, pk2, c1, c2, cl_cl_proof);
    // std::cout << "cl_cl_proof_res: " << verify_res << std::endl;
    // auto encrypt_proof = C.encrypt_proof(pk1, c1, m, r1, randgen);
    // auto verify_res2 = C.encrypt_verify(pk1, c2, encrypt_proof);
    // std::cout << "encrypt_proof_res: " << verify_res2 << std::endl;

    // C.power_of_h (gp_r1, Mpz("72048742277494395339533061984139355904610663484117275638395963297495883454538"));
    // C.power_of_h (gp_r2, Mpz("70795547422516615862889718024772333991937014393068567817406786413659743186496"));
    // // std::cout << "gp_r1: " << qfi_to_str(gp_r1) << std::endl;
    // // std::cout << "gp_r2: " << qfi_to_str(gp_r2) << std::endl;
    // C.power_of_h (gp_r, Mpz("27052200462694815778851795000223782043710113598110939073197586569637465146697"));
    // C.power_of_h (order, Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));

    // 验证gp^r1 * gp^r2 = gp^r  其中 r = r1 + r2
    QFI gp_r1, gp_r2, gp_r, gp_r_, order, order_add, G_add, DeltaK_add;
    C.power_of_h (gp_r1, Mpz("72048742277494395339533061984139355904610663484117275638395963297495883454538"));
    std::cout << "gp_r1 初始: " << qfi_to_str(gp_r1) << std::endl;
    C.power_of_h (gp_r2, Mpz("70795547422516615862889718024772333991937014393068567817406786413659743186496"));
    // std::cout << "gp_r1: " << qfi_to_str(gp_r1) << std::endl;
    // std::cout << "gp_r2: " << qfi_to_str(gp_r2) << std::endl;
    C.power_of_h (gp_r, Mpz("27052200462694815778851795000223782043710113598110939073197586569637465146697"));
    C.power_of_h (order, Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 10000; i++){
        CL_HSMqk C(generate_C());
        QFI res;
        C.Cl_G().nucomp (gp_r1, gp_r1, gp_r1);
        std::string res_str =  qfi_to_str(res);
        const char* res_char = res_str.c_str();
        strdup(res_char); 
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "qfi add cpp time: " << duration2 << "us" << std::endl;
    start = std::chrono::steady_clock::now();
    for(int i = 0; i < 10000; i++){
        CL_HSMqk C(generate_C());
        QFI res;
        C.Cl_G().nupow (gp_r1, gp_r1, Mpz("72048742277494395339533061984139355904610663484117275638395963297495883454538"));
        std::string res_str =  qfi_to_str(res);
        const char* res_char = res_str.c_str();
        strdup(res_char); 
        
    }
    end = std::chrono::steady_clock::now();
    duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "qfi mul cpp time: " << duration2 << "us" << std::endl;
    // C.power_of_h (gp_r1, Mpz("31829213739508382526057504669095674267313712848053184198077385423896039397450"));
    // C.power_of_h (gp_r2, Mpz("30576018884530603049414160709728652354640063757004476377088208540059899129408"));
    // // std::cout << "gp_r1: " << qfi_to_str(gp_r1) << std::endl;
    // // std::cout << "gp_r2: " << qfi_to_str(gp_r2) << std::endl;
    // C.power_of_h (gp_r, Mpz("22185704086052972761996108063780644984656825968993569134847016090356094469770"));
    // C.power_of_h (order, Mpz("40219528537986012813475557315043681637296950636064091440318577873599844057088"));
    // C.Cl_G().nucomp (G_add, gp_r1, gp_r2);
    // C.Cl_G().nucomp (DeltaK_add, gp_r1, gp_r2);
    // std::cout << "G_add: " << qfi_to_str(G_add) << std::endl;
    // std::cout << "DeltaK_add: " << qfi_to_str(DeltaK_add) << std::endl;
    // C.Cl_G().nucompinv (gp_r2, gp_r2, order);
    C.from_Cl_DeltaK_to_Cl_Delta (gp_r1);
    C.from_Cl_DeltaK_to_Cl_Delta (gp_r2);
    std::cout << "gp_r1: " << qfi_to_str(gp_r1) << std::endl;
    std::cout << "gp_r2: " << qfi_to_str(gp_r2) << std::endl;
    C.Cl_Delta().nucomp (gp_r_, gp_r1, gp_r2);
    // gp_r_.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK());
    // gp_r_.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK());
    // gp_r.to_maximal_order (Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"), C.DeltaK());
    // gp_r_.lift(Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    // gp_r.lift(Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    // C.Cl_DeltaK().nupow(gp_r_, gp_r_, Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    // C.Cl_DeltaK().nupow(gp_r, gp_r, Mpz("115792089237316195423570985008687907852837564279074904382605163141518161494337"));
    // C.Cl_G().nucompinv (gp_r_, gp_r_, order);
    // C.Cl_DeltaK().nucomp(gp_r_, gp_r1, gp_r2);
    // CL_q.nucomp(gp_r_, gp_r1, gp_r2);
    // C.Cl_G().nucomp (order_add, order, gp_r);
    // C.Cl_G().nupow (gp_r_, gp_r_, Mpz("1"));
    C.from_Cl_DeltaK_to_Cl_Delta (gp_r);
    std::cout << "gp_r: " << qfi_to_str(gp_r) << std::endl;
    std::cout << "gp_r_: " << qfi_to_str(gp_r_) << std::endl;
    // // std::cout << "order_add: " << qfi_to_str(order_add) << std::endl;

    // std::cout << "G_class_number_bound: " << C.Cl_G().class_number_bound() << std::endl;
    // std::cout << "G_default_nucomp_bound: " << C.Cl_G().default_nucomp_bound() << std::endl;
    // std::cout << "Delta_class_number_bound: " << C.Cl_Delta().class_number_bound() << std::endl;
    // std::cout << "Delta_default_nucomp_bound: " << C.Cl_Delta().default_nucomp_bound() << std::endl;
    // std::cout << "DeltaK_class_number_bound: " << C.Cl_DeltaK().class_number_bound() << std::endl;
    // std::cout << "DeltaK_default_nucomp_bound: " << C.Cl_DeltaK().default_nucomp_bound() << std::endl;
    // Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    // Mpz m1("72048742277494395339533061984139355904610663484117275638395963297495883454538");
    // Mpz m2("70795547422516615862889718024772333991937014393068567817406786413659743186496");
    // auto pk = public_key_gen_cpp("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    // auto cipher1 = encrypt_cpp(pk, "72048742277494395339533061984139355904610663484117275638395963297495883454538", r.tostring().c_str());
    // auto cipher2 = encrypt_cpp(pk, "70795547422516615862889718024772333991937014393068567817406786413659743186496", r.tostring().c_str());
    // auto cipher_res = add_ciphertexts_cpp(cipher1, cipher2);
    // std::cout << "m_add: " << decrypt_cpp("115792089237316195423570985008687907852837564279074904382605163141518161494337", cipher_res) << std::endl;
    // auto sk1_test = "2";
    // // auto sk2_test = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
    // auto sk2_test = "1";
    // auto sk_total = "115792089237316195423570985008687907852837564279074904382605163141518161494339";
    // auto pk_test = public_key_gen_cpp("55270412688465749158587498419807288397565550794173458926913749022636170058228");
    // Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    // auto cipher_test = encrypt_cpp(pk_test, "123", r.tostring().c_str());
    // auto c1 = get_c1(cipher_test);
    // auto c2 = get_c2(cipher_test);
    // auto c1_sk1 = sk_power_of_c1_cpp(c1, sk1_test);
    // auto c1_sk2 = sk_power_of_c1_cpp(c1, sk2_test);
    // auto c1_total = add_c1(c1_sk1, c1_sk2);
    // std::cout << "c1_total: " << c1_total << std::endl;
    // auto c1_total_ = sk_power_of_c1_cpp(c1, sk_total);
    // std::cout << "c1_total_: " << c1_total_ << std::endl;
    // auto sk1 = "64948958375134249729069669027838288483335754048776730854343499475454240885116";
    // auto sk2 = "52213317170554212069809401591211979481034823371161523772791719686051122001819";
    // auto pk_total = public_key_gen_cpp("1370186308372266375308085610362360111533013140863350244530056019987201392598");
    // Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
    // auto cipher = encrypt_cpp(pk_total, "123", r.tostring().c_str());
    // auto c1 = get_c1(cipher);
    // auto c2 = get_c2(cipher);
    // auto c1_sk1 = sk_power_of_c1_cpp(c1, sk1);
    // auto c1_sk2 = sk_power_of_c1_cpp(c1, sk2);
    // auto c1_total = add_c1(c1_sk1, c1_sk2);
    // auto m = multi_decrypt_cpp(c1_total, c2);
    // std::cout << "m: " << m << std::endl;

    // auto pk1 =  public_key_gen_cpp("64948958375134249729069669027838288483335754048776730854343499475454240885116");
    // auto pk2 =  public_key_gen_cpp("52213317170554212069809401591211979481034823371161523772791719686051122001819");

    // Mpz r_a(randgen.random_mpz (C.encrypt_randomness_bound()));
    // Mpz r_b(randgen.random_mpz (C.encrypt_randomness_bound()));

    // auto cipher_a = encrypt_cpp(pk1, "123", r_a.tostring().c_str());
    // auto cipher_b = encrypt_cpp(pk2, "123",  r_b.tostring().c_str());

    // auto encrypt_proof = encrypt_prove_cpp(pk1, cipher_a, "123", r_a.tostring().c_str());
    // auto encrypt_verify = encrypt_verify_cpp(encrypt_proof, pk1, cipher_a);

    // std::cout << "encrypt_verify_res: " << encrypt_verify << std::endl;

    // auto cl_cl_proof = cl_cl_prove_cpp(pk1, pk2, cipher_a, cipher_b, "123", r_a.tostring().c_str(), r_b.tostring().c_str());
    // auto cl_cl_verify = cl_cl_verify_cpp(cl_cl_proof, pk1, pk2, cipher_a, cipher_b);

    //  std::cout << "cl_cl_verify_res: " << cl_cl_verify << std::endl;
}