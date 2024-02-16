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
    const char* encrypt_enc_cpp(const char* pk_str, const char* message, const char* random);
    const char* decrypt_enc_cpp(const char* sk_str, const char* cipher_str);
    const char* add_ciphertexts_cpp(const char* cipher_str_first, const char* cipher_str_second);
    const char* add_ciphertexts_enc_cpp(const char* cipher_str_first, const char* cipher_str_second);
    const char* scal_ciphertexts_cpp(const char* cipher_str, const char* m_str);
    const char* encrypt_prove_cpp(const char* pk_str, const char* cipher_str, const char* m_str, const char* r_str);
    const char* encrypt_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str);
    const char* cl_ecc_prove_cpp(const char* pk_str, const char* cipher_str, const char* commit_str, const char* m_str, const char* r_str);
    const char* cl_ecc_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* commit_str);
    const char* cl_enc_com_prove_cpp(const char* pk_str, const char* cipher_str, const char* com_str, const char* m_str, const char* r_str);
    const char* cl_enc_com_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* com_str);
    const char* qfi_add_cpp(const char* qfi1_str, const char* qfi2_str);
    // const char* qfi_add_hash_cpp(const char* qfi1_str, const char* qfi2_str);
    const char* qfi_mul_cpp(const char* qfi_str, const char* mpz_str);
    // const char* qfi_mul_hash_cpp(const char* qfi_str, const char* mpz_str);
    const char* power_of_h_cpp(const char* x_str);
    const char* calculate_commit_cpp(const char* x_str, const char* delta_str);
    const char* calculate_commitments_cpp(const char* coefficients_str, const char* delta_str);
    const char* verify_share_cpp(const char* commitments_str, const char* secret_share_str, const char* index_str, const char* delta_str);
    const char* verify_share_commit_cpp(const char* commitments_str, const char* share_commit_str, const char* index_str, const char* delta_str);
    const char* get_qfi_zero_cpp();
    const char* decrypt_c1_cpp(const char* cipher_str, const char* sk_str, const char* delta_str);
    const char* multi_decrypt_cpp(const char* c1_str, const char* cipher_str, const char* delta_str);
    const char* pre_calculate_pk_cpp(const char* pk_str);
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
/*
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
*/

CL_HSMqk generate_C_enc(){
    Mpz q_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz p_ ("7");
    Mpz fud_ ("680564733841876926926749214863536422912");
    Mpz M_ ("13407807929942597099574024998205846127379224100613902121136927097058285002635891330411377376978090146667648480129683279260917149325652956599247552883069569");
    Mpz exponent_bound_ ("519825222697581994973081647134787959795934971297792");
    size_t d = 85;
    size_t e = 43;
    std::string h_str = "46629774537105562317587909455371409373 5 -610103069260304645 1 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto e_precomp_str = "456547826580792566033679258631881451051 1 -768321955341591265 0 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto d_precomp_str =  "467802962743283914053915527065451326487 1 -9396857810162542246 0 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto de_precomp_str =  "27382569778555061866722233597103258019 1 -3493349645387087857 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    CL_HSMqk C (q_, 2, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}

CL_HSMqk generate_C(){
    Mpz q_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz p_ ("7");
    Mpz fud_ ("1099511627776");
    // CL_HSMqk C(q_, 1, p_, true);
    // std::cout << "fud" << C.fud_factor() <<std::endl;
    // std::cout << "M: " << C.M() << std::endl;
    // std::cout << "exponent_bound" << C.secretkey_bound() <<std::endl;
    // std::cout << "d" << C.d() <<std::endl;
    // std::cout << "e" << C.e() <<std::endl;
    // std::cout << "h" << qfi_to_str(C.h()) <<std::endl;
    // std::cout << "e_pre" << qfi_to_str(C.h_e_precomp()) <<std::endl;
    // std::cout << "d_pre" << qfi_to_str(C.h_d_precomp()) <<std::endl;
    // std::cout << "de_pre" << qfi_to_str(C.h_de_precomp()) <<std::endl;
    Mpz M_ ("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Mpz exponent_bound_ ("519825222697581994973081647134787959795934971297792");
    size_t d = 85;
    size_t e = 43;
    std::string h_str = "144981785181062899352360633526556264162 1 -3094606589199551713 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto e_precomp_str = "29430119204407461226734121732711590338 1 1396069299632702381 0 true -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto d_precomp_str =  "77604097034434070520838802221803506438 1 113927739220299871 0 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    auto de_precomp_str =  "3201118217763513943109252430225497086 115 89241095639766715 29 false -810544624661213367964996895060815354969862949953524330678236141990627130460359";
    CL_HSMqk C (q_, 1, p_, fud_, M_, str_to_qfi(h_str), exponent_bound_, d, e, str_to_qfi(e_precomp_str), str_to_qfi(d_precomp_str), str_to_qfi(de_precomp_str), true, true);
    return C;
}

const char* public_key_gen_cpp(const char* sk_str){
    CL_HSMqk C = generate_C_enc();
   
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

const char* encrypt_enc_cpp(const char* pk_str, const char* message, const char* random){
    CL_HSMqk C(generate_C_enc());

    CL_HSMqk::ClearText  m (C, Mpz (message));

    CL_HSMqk::PublicKey pk =  str_to_pk(pk_str);

    BICYCL::CL_HSMqk::CipherText c = C.encrypt(pk, m, Mpz (random));
    std::string cipher_str =  qfi_to_str(c.c1()) + ":" + qfi_to_str(c.c2());

    const char* cipher_char = cipher_str.c_str();
    return strdup(cipher_char);
}

const char* decrypt_enc_cpp(const char* sk_str, const char* cipher_str){
     CL_HSMqk C(generate_C_enc());

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

const char* add_ciphertexts_enc_cpp(const char* cipher_str_first, const char* cipher_str_second){
    CL_HSMqk C(generate_C_enc());

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

const char* multi_decrypt_cpp(const char* c1_str, const char* cipher_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    
    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    QFI fm = str_to_qfi(c1_str);
    if (C.compact_variant())
    C.from_Cl_DeltaK_to_Cl_Delta (fm);

    QFI c2;
    C.Cl_Delta().nupow (c2, str_to_qfi(cipher_vec[1]), Mpz (delta_str));
    C.Cl_Delta().nupow (c2, c2, Mpz (delta_str));
    C.Cl_Delta().nupow (c2, c2, Mpz (delta_str));

    C.Cl_Delta().nucompinv (fm, c2, fm); /* c2/c1^sk */

    Mpz m = C.dlog_in_F(fm);

    std::string m_str = m.tostring();
    const char* m_char = m_str.c_str();
    return strdup(m_char);
}

const char* decrypt_c1_cpp(const char* cipher_str, const char* sk_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    
    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    QFI res;
    C.Cl_G().nupow (res, str_to_qfi(cipher_vec[0]), Mpz (sk_str));
    C.Cl_G().nupow (res, res, Mpz (delta_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
    
}

const char* pre_calculate_pk_cpp(const char* pk_str){
    CL_HSMqk C(generate_C());
    CL_HSMqk::PublicKey pk = C.keygen(str_to_qfi(pk_str));
    std::string res_str =  pk_to_str(pk);
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

const char* cl_enc_com_prove_cpp(const char* pk_str, const char* cipher_str, const char* com_str, const char* m_str, const char* r_str){
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    CL_HSMqk C_enc(generate_C_enc());
    CL_HSMqk C_dkg(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    BICYCL::CL_HSMqk::ClearText m (C_enc, Mpz (m_str));

    auto proof =  C_enc.cl_enc_com_proof(C_dkg ,pk, c, str_to_qfi(com_str), m, Mpz(r_str), randgen);
    std::string proof_str = proof.cl_enc_com_toString();
    const char* proof_char = proof_str.c_str();
    return strdup(proof_char);
}

const char* cl_enc_com_verify_cpp(const char* proof_str, const char* pk_str, const char* cipher_str, const char* com_str){

    std::vector<std::string> proof_vec = splitString(proof_str, ' ');
    Mpz zm(proof_vec[0]);
    Mpz zr(proof_vec[1]);
    Mpz e(proof_vec[2]);
    CL_HSMqk::CL_Enc_Com_Proof proof(zm, zr, e);

    CL_HSMqk C_enc(generate_C_enc());
    CL_HSMqk C_dkg(generate_C());

    CL_HSMqk::PublicKey pk = str_to_pk(pk_str);

    std::vector<std::string> cipher_vec = splitString(cipher_str, ':');
    CL_HSMqk::CipherText c(str_to_qfi(cipher_vec[0]), str_to_qfi(cipher_vec[1]));

    auto verify = C_enc.cl_enc_com_verify(C_dkg, pk, c, str_to_qfi(com_str), proof);
    const std::string res = (verify) ? "true" : "false";

    const char* res_char = res.c_str();
    return strdup(res_char);
}

const char* qfi_add_cpp(const char* qfi1_str, const char* qfi2_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.Cl_G().nucomp (res, str_to_qfi(qfi1_str), str_to_qfi(qfi2_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

// const char* qfi_add_hash_cpp(const char* qfi1_str, const char* qfi2_str){
//     CL_HSMqk C(generate_C_hash());
//     QFI res;
//     C.Cl_G().nucomp (res, str_to_qfi(qfi1_str), str_to_qfi(qfi2_str));
//     std::string res_str =  qfi_to_str(res);
//     const char* res_char = res_str.c_str();
//     return strdup(res_char);
// }

const char* qfi_mul_cpp(const char* qfi_str, const char* mpz_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.Cl_G().nupow (res, str_to_qfi(qfi_str), Mpz(mpz_str));
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

// const char* qfi_mul_hash_cpp(const char* qfi_str, const char* mpz_str){
//     CL_HSMqk C(generate_C_hash());
//     QFI res;
//     C.Cl_G().nupow (res, str_to_qfi(qfi_str), Mpz(mpz_str));
//     std::string res_str =  qfi_to_str(res);
//     const char* res_char = res_str.c_str();
//     return strdup(res_char);
// }

const char* power_of_h_cpp(const char* x_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.power_of_h (res, Mpz(x_str)); /* res = h^x */
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* calculate_commit_cpp(const char* x_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    QFI res;
    C.power_of_h (res, Mpz(x_str)); /* res = h^x */
    C.Cl_G().nupow (res, res, Mpz(delta_str)); /* res = h^（x * delta）*/
    std::string res_str =  qfi_to_str(res);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* calculate_commitments_cpp(const char* coefficients_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    std::vector<std::string> coefficients_vec = splitString(coefficients_str, ':');
    std::string res_str = "";
    for(int i = 0; i < coefficients_vec.size(); i++){
        QFI commit;
        C.power_of_h (commit, Mpz(coefficients_vec[i])); /* res = h^x */
        C.Cl_G().nupow (commit, commit, Mpz(delta_str)); /* res = h^（x * delta）*/
        res_str += qfi_to_str(commit);
        if(i != coefficients_vec.size() - 1)
            res_str += ":";
    }
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* verify_share_cpp(const char* commitments_str, const char* secret_share_str, const char* index_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    QFI lift, right;
    /* lift = h^(yi * delta)*/
    C.power_of_h (lift, Mpz(secret_share_str));
    C.Cl_G().nupow (lift, lift, Mpz(delta_str)); 
    /* right = c0 ^ (delta * delta) + ck ^ ik */
    std::vector<std::string> commitments_vec = splitString(commitments_str, ':');
    C.Cl_G().nupow (right, str_to_qfi(commitments_vec[0]), Mpz(delta_str));
    C.Cl_G().nupow (right, right, Mpz(delta_str));
    Mpz index_pow_k(index_str);
    for(int k = 1; k < commitments_vec.size(); k++){
        QFI temp;
        C.Cl_G().nupow (temp, str_to_qfi(commitments_vec[k]), index_pow_k);
        C.Cl_G().nucomp(right, right, temp);
        Mpz::mul(index_pow_k, index_pow_k, Mpz(index_str));
    }
    std::string res_str = "";
    
    if(lift == right){
        res_str = "true";
    }else{
        res_str = "false";
    }
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* verify_share_commit_cpp(const char* commitments_str, const char* share_commit_str, const char* index_str, const char* delta_str){
    CL_HSMqk C(generate_C());
    QFI lift, right;
    /* lift = h^(yi * delta)*/
    C.Cl_G().nupow (lift, str_to_qfi(share_commit_str), Mpz(delta_str)); 
    /* right = c0 ^ (delta * delta) + ck ^ ik */
    std::vector<std::string> commitments_vec = splitString(commitments_str, ':');
    C.Cl_G().nupow (right, str_to_qfi(commitments_vec[0]), Mpz(delta_str));
    C.Cl_G().nupow (right, right, Mpz(delta_str));
    Mpz index_pow_k(index_str);
    for(int k = 1; k < commitments_vec.size(); k++){
        QFI temp;
        C.Cl_G().nupow (temp, str_to_qfi(commitments_vec[k]), index_pow_k);
        C.Cl_G().nucomp(right, right, temp);
        Mpz::mul(index_pow_k, index_pow_k, Mpz(index_str));
    }
    std::string res_str = "";
    
    if(lift == right){
        res_str = "true";
    }else{
        res_str = "false";
    }
    const char* res_char = res_str.c_str();
    return strdup(res_char);
}

const char* get_qfi_zero_cpp(){
    QFI zero (Mpz("1"), Mpz("1"), Mpz("202636156165303341991249223765203838742465737488381082669559035497656782615090"));
    std::string res_str =  qfi_to_str(zero);
    const char* res_char = res_str.c_str();
    return strdup(res_char);
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
     CL_HSMqk::CipherText c = C.encrypt(pk, m, randgen);
    std::cout << "m: " << m << std::endl;
    auto start = std::chrono::steady_clock::now();
    for(int i = 0; i < 1000; i++){
        CL_HSMqk C(generate_C());
        QFI res;
        C.power_of_h (res, m); /* res = h^x */
        std::string res_str =  qfi_to_str(res);
        const char* res_char = res_str.c_str();
        strdup(res_char);
    }
    auto end = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "power of h time: " << duration2 << "us" << std::endl;
    start = std::chrono::steady_clock::now();
    auto qfi = qfi_to_str(c.c1());
    for(int i = 0; i < 1000; i++){
        CL_HSMqk C(generate_C());
        QFI res;
        C.Cl_G().nupow (res, str_to_qfi(qfi), m, C.d(), C.e(), C.h_e_precomp(), C.h_d_precomp(), C.h_de_precomp());
        std::string res_str =  qfi_to_str(res);
        const char* res_char = res_str.c_str();
        strdup(res_char);
    }
    end = std::chrono::steady_clock::now();
    duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "qfi mul time: " << duration2 << "us" << std::endl;
}

int main(){
    // test_run_time();

    // CL_HSMqk::CipherText c2 = C.encrypt(pk2, m_wrong, r2);
    // auto cl_cl_proof = C.cl_cl_proof(pk1, pk2, c1, c2, m, r1, r2, randgen);
    // auto verify_res =  C.cl_cl_verify(pk1, pk2, c1, c2, cl_cl_proof);
    // std::cout << "cl_cl_proof_res: " << verify_res << std::endl;
    // auto encrypt_proof = C.encrypt_proof(pk1, c1, m, r1, randgen);
    // auto verify_res2 = C.encrypt_verify(pk1, c2, encrypt_proof);
    // std::cout << "encrypt_proof_res: " << verify_res2 << std::endl;
    RandGen randgen;
    BICYCL::Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);
    CL_HSMqk C(generate_C_enc());
    Mpz delta("24");
    Mpz l1("72"); 
    Mpz l2("-72");
    Mpz l3("24");
    Mpz sk1("179165613560161423884730595219306211049835900162048925289178744203662879005568");
    Mpz sk2("358331227120322847769461156904756725694411099369651544015275029752114738517984");
    Mpz sk3("537496840680484271654191718590207240338986298577254162741371315300566598030400");
    // auto pk = pre_calculate_pk_cpp("102944310025125528913342843259281740748 2 -5493999393494669861 1 true -810544624661213367964996895060815354969862949953524330678236141990627130460359");
    // auto cipher = encrypt_hash_cpp(pk, "123", "53749684068048427165419171859");
    // auto dec_c1_1 = decrypt_c1_cpp(cipher, "179165613560161423884730595219306211049835900162048925289178744203662879005568", "24");
    // auto dec_c1_2 = decrypt_c1_cpp(cipher, "358331227120322847769461156904756725694411099369651544015275029752114738517984", "24");
    // auto dec_c1_3 = decrypt_c1_cpp(cipher, "537496840680484271654191718590207240338986298577254162741371315300566598030400", "24");

    // auto res = get_qfi_zero_cpp();
    // auto temp = qfi_mul_hash_cpp(dec_c1_1, "72");
    // res = qfi_add_hash_cpp(res, temp);
    // temp = qfi_mul_hash_cpp(dec_c1_2, "-72");
    // res = qfi_add_hash_cpp(res, temp);
    // temp = qfi_mul_hash_cpp(dec_c1_3, "24");
    // res = qfi_add_hash_cpp(res, temp);

    // // auto m = multi_decrypt_cpp(res, cipher, "24");
    // // std::cout << "m: " << m << std::endl;
}