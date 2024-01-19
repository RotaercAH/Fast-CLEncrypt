/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef CL_HSMqk_HPP__
#define CL_HSMqk_HPP__

#include <iostream>
#include <tuple>
#include <stdexcept>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>


#include "../bicycl/openssl_wrapper.hpp"
#include "../bicycl/gmp_extras.hpp"
#include "../bicycl/qfi.hpp"
// #include "bicycl/CL_HSM_utils.hpp"
#include "../bicycl/seclevel.hpp"
#include "../bicycl/CL_HSM_utils.hpp"

namespace BICYCL
{
  /**
   * Class for the cryptosystem based on the hidden subgroup membership problem.
   *
   * Ref: ??
   */
  class CL_HSMqk
  {
    protected:
      /** an odd prime. */
      Mpz q_;

      /** an positive integer */
      size_t k_;

      /** an odd prime or 1. */
      Mpz p_;

      /** q^k */
      Mpz M_;

      /** \f$ \ClDeltaK \f$ : the class group of the maximal order.
       * Its discriminant is equal to \f$ -p \times q \f$.
       */
      ClassGroup Cl_DeltaK_;

      /** \f$ \ClDelta \f$: the class group of the order of conductor
       * \f$M=q^k\f$.
       * Its discriminant is equal to \f$ -p \times q^{2k+1} \f$.
       * It contains the subgroup \f$F\f$.
       */
      ClassGroup Cl_Delta_;

      /** \c true if the compact variant is used, \c false otherwise. */
      bool compact_variant_;

      /** \c true if the large-message variant is used, \c false otherwise. */
      bool large_message_variant_;

      /** The generator of the group \f$H\f$.
       * If the compact variant is not used, the generator is an element of
       * \f$ \ClDelta \f$, else it is an element of \f$ \ClDeltaK \f$.
       */
      QFI h_;

      Mpz fud_factor_; /* folded uniform distribution factor */
      Mpz exponent_bound_; /* actual bound use to draw random values; is equal
                            * to fud_factor_ times Cl_Delta_.class_number_bound_
                            */
      /** Precomputation data: a positive integer */
      size_t d_;
      size_t e_;
      /** Precomputation data: h_^(2^e_), h_^(2^d_), h_^(d_+e_) */
      QFI h_e_precomp_;
      QFI h_d_precomp_;
      QFI h_de_precomp_;

    public:
      /** Class used to represent a secret key of the cryptosystem */
      using SecretKey = _Utils::CL_HSM_SecretKey<CL_HSMqk>;
      /** Class used to represent a public key of the cryptosystem */
      using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
      /** Class used to represent a cleartext for the cryptosystem */
      using ClearText = _Utils::CL_HSM_ClearText<CL_HSMqk>;
      /** Class used to represent a ciphertext for the cryptosystem */
      using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;
      /** Type to store the genus of of an element of the class group */
      using Genus = std::tuple<int, int>;

      /**
       * @name Constructors
       *
       * Setup of the cryptosystem
       *
       *@{
       */
       /**
       * Setup of the cryptosystem given @p q and @p p and @h h and.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor, const Mpz &M, const QFI &h, const Mpz &exponent_bound, const size_t d, const size_t e, const QFI &h_e_precomp, 
                     const QFI &h_d_precomp, const QFI &h_de_precomp ,bool compact_variant, bool large_message_variant);
      /**
       * Setup of the cryptosystem given @p q and @p p.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor,
           bool compact_variant);
      /**
       * Same as above, using default value `false` for @p compact_variant.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor);
      /**
       * Same as above, using default value for @p fud_factor.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, bool compact_variant);
      /**
       * Same as above, using default values.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p);
      /**
       * Copy constructor, only the value of compact variant can be changed.
       */
      CL_HSMqk (const CL_HSMqk &C, bool compact_variant);
      /**
       * Setup of the cryptosystem given @p q and the size of \f$\Delta_K\f$@p.
       */
      template <class... Ts>
      CL_HSMqk (const Mpz &q, size_t k, size_t DeltaK_nbits, RandGen &randgen,
                                                             Ts... args);
      /**
       * Setup of the cryptosystem given the size of @p q and the size of
       * \f$\Delta_K\f$@p.
       */
      template <class... Ts>
      CL_HSMqk (size_t q_nbits, size_t k, size_t DeltaK_nbits, RandGen &randgen,
                                                               Ts... args);
      /**
       * Setup of the cryptosystem given @p q and the desired security level.
       *
       * The equivalence between security level and the size of \f$\Delta_K\f$
       * can be found in the class \ref SecLevel.
       */
      template <class... Ts>
      CL_HSMqk (const Mpz &q, size_t k, SecLevel seclevel, RandGen &randgen,
                                                           Ts... args);
      /**
       * Setup of the cryptosystem given the size of @p q and the desired
       * security level.
       *
       * The equivalence between security level and the size of \f$\Delta_K\f$
       * can be found in the class \ref SecLevel.
       */
      template <class... Ts>
      CL_HSMqk (size_t q_nbits, size_t k, SecLevel seclevel, RandGen &randgen,
                                                             Ts... args);
      /**@}*/

      /**
       * @name Public methods to retrieve the public parameters
       *@{
       */
      /** Return k */
      size_t k () const;
      /** Return e */
      size_t e () const;
      /** Return d */
      size_t d () const;
      /** Return q, the cardinality of the subgroup \f$F\f$ is \f$M=q^k\f$. */
      const Mpz & q () const;
      /** Return p, a odd prime or 1. */
      const Mpz & p () const;
      /** Return \f$M=q^{k}\f$, the conductor of \f$\Delta\f$. */
      const Mpz & M () const;
      /** Return \f$\Delta_K = -pq\f$. */
      const Mpz & DeltaK () const;
      /** Return \f$\Delta = -pq^{2k+1}\f$. */
      const Mpz & Delta () const;
      /** Return fud_factor**/
      const Mpz & fud_factor () const;

      /**
       * Return \f$\ClDeltaK\f$: the class group of discriminant
       * \f$\Delta_K = -pq\f$.
       */
      const ClassGroup & Cl_DeltaK () const;
      /**
       * Return \f$\ClDelta\f$: the class group of discriminant
       * \f$\Delta = -pq^{2k+1}\f$.
       */
      const ClassGroup & Cl_Delta () const;
      const ClassGroup & Cl_G () const;
      /** Return \f$h\f$, the generator of the cyclic subgroup \f$H\f$ */
      const QFI & h () const;
      /** Return \f$h_e_precomp\f$ */
      const QFI & h_e_precomp () const;
      /** Return \f$h_d_precomp\f$ */
      const QFI & h_d_precomp () const;
      /** Return \f$h_de_precomp\f$ */
      const QFI & h_de_precomp () const;
      /** Return whether the compact variant is used or not */
      bool compact_variant () const;
      /** Return whether the large message variant is used or not */
      bool large_message_variant () const;
      /** Return the bound for secret keys: the bound on the size of \f$H\f$ */
      const Mpz & secretkey_bound () const;
      /** Return the bound for cleartexts: \f$M=q^k\f$ */
      const Mpz & cleartext_bound () const;
      /** Return the bound for random exponents: same as #secretkey_bound */
      const Mpz & encrypt_randomness_bound () const;
      /**@}*/

      /**
       * @name Public methods for computation in subgroups
       *@{
       */
      /** Set @p r to \f$h^e\f$, where #h is the generator of \f$H\f$. */
      void power_of_h (QFI &r, const Mpz &e) const;
      /** Return \f$f^m\f$, where `f` is the generator of \f$F\f$. */
      QFI power_of_f (const Mpz &m) const;
      /** Return the discrete logarithm of the form @p fm. */
      Mpz dlog_in_F (const QFI &fm) const;
      /**
       * Compute \f$\psi_{q^k}(f)\f$ to move @p f from \f$\Delta_K\f$ to
       * \f$\Delta\f$.
       */
      void from_Cl_DeltaK_to_Cl_Delta (QFI &f) const;
      /** Compute the genus of the form f */
      Genus genus (const QFI &f) const;
      /**@}*/

      /**
       * @name Public methods implementing the cryptographic functionalities
       *@{
       */
      /** Generate a secret key from mpz*/
      SecretKey keygen (Mpz &sk) const;
      /** Generate a random secret key */
      SecretKey keygen (RandGen &randgen) const;
      /** Compute the public key associated to a secret key */
      PublicKey keygen (const SecretKey &sk) const;
      /** Encrypt @p m using public key @p pk */
      CipherText encrypt (const PublicKey &pk, const ClearText &m,
                          RandGen &randgen) const;
      /** Encrypt @p m using public key @p pk and randomness @p r*/
      CipherText encrypt (const PublicKey &pk, const ClearText &m,
                          const Mpz&r) const;
      /** Decrypt @p c using secret key @p sk*/
      ClearText decrypt (const SecretKey &sk, const CipherText &c) const;
      /** Homomorphically add ciphertexts @p ca and @p cb */
      CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, RandGen &randgen) const;
      /** Homomorphically add ciphertexts @p ca and @p cb using @p r */
      CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, const Mpz &r) const;
      /** Homomorphically add ciphertexts @p ca and @p cb without @p r */
      CipherText add_ciphertexts (const CipherText &ca, const CipherText &cb) const;
      /** Add the two cleartexts @p ma and @p mb */
      ClearText add_cleartexts (const ClearText &ma, const ClearText &mb) const;
      /** Homomorphically compute @p s times @p c */
      CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                   const Mpz &s, RandGen &randgen) const;
      /** Homomorphically compute @p s times @p c using @p r*/
      CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                   const Mpz &s, const Mpz &r) const;
      /** Homomorphically compute @p s times @p c without @p r*/
      CipherText scal_ciphertexts (const CipherText &c, const Mpz &s) const;
      /** Compute @p s times @p m */
      ClearText scal_cleartexts (const ClearText &m, const Mpz &s) const;
      /**@}*/

      /** Print the public parameters of the cryptosystem */
      friend std::ostream & operator<< (std::ostream &, const CL_HSMqk &);

      class Encrypt_Proof
      {
        protected:
          Mpz zm_;
          Mpz zr_;
          Mpz e_;

        public:
          Encrypt_Proof (const CL_HSMqk &C, const PublicKey &pk,
                 const CipherText &c, const ClearText &m, const Mpz &r,
                 RandGen &randgen);

          Encrypt_Proof (const Mpz zm, const Mpz zr, const Mpz e);

          bool Encrypt_verify (const CL_HSMqk &, const PublicKey &pk,
                       const CipherText &) const;

           std::string encrypt_toString() const;

        protected:
          Mpz generate_hash (const CL_HSMqk &C, const PublicKey &pk,
                           const CipherText &c, const QFI &t1,
                           const QFI &t2) const;
          
      };

      class CL_ECC_Proof
      {
        protected:
          Mpz zm_;
          Mpz zr_;
          Mpz e_;

        public:
          CL_ECC_Proof (const CL_HSMqk &C, const PublicKey &pk,
                 const CipherText &c, const EC_POINT *commit, const ClearText &m, const Mpz &r, 
                 RandGen &randgen);
          
          CL_ECC_Proof (const Mpz zm, const Mpz zr, const Mpz e);

          bool CL_ECC_verify (const CL_HSMqk &, const PublicKey &pk,
                       const CipherText &, const EC_POINT *commit) const;

          std::string cl_ecc_toString() const;
          

        protected:
          Mpz generate_hash (const CL_HSMqk &C, const PublicKey &pk,
                           const CipherText &c, const EC_POINT *T, const QFI &t1,
                           const QFI &t2) const;
          
      };

      class CL_CL_Proof
      {
        protected:
          Mpz zm_;
          Mpz zr1_;
          Mpz zr2_;
          Mpz e_;

        public:
          CL_CL_Proof (const CL_HSMqk &C, const PublicKey &pk1, const PublicKey &pk2,
                 const CipherText &c1, const CipherText &c2, const ClearText &m, const Mpz &r1, const Mpz &r2,
                 RandGen &randgen);
          
          CL_CL_Proof (const Mpz zm, const Mpz zr1, const Mpz zr2, const Mpz e);

          bool CL_CL_verify (const CL_HSMqk &, const PublicKey &pk1, const PublicKey &pk2,
                       const CipherText &, const CipherText &) const;

          std::string cl_cl_toString() const;
          

        protected:
          Mpz generate_hash (const CL_HSMqk &C, const PublicKey &pk1, const PublicKey &pk2, 
                           const CipherText &c1, const CipherText &c2, const QFI &t1_1, const QFI &t1_2, const QFI &t2_1, const QFI &t2_2) const;
      };
      /* */
      Encrypt_Proof encrypt_proof (const PublicKey &pk, const CipherText &c,
                                  const ClearText &m, const Mpz &r, RandGen &randgen) const;
      bool encrypt_verify (const PublicKey &pk, const CipherText &c, const Encrypt_Proof &proof) const;

      /* */
      CL_ECC_Proof cl_ecc_proof (const PublicKey &pk, const CipherText &c, const EC_POINT *commit, const ClearText &m, const Mpz &r,
                                  RandGen &randgen) const;
      bool cl_ecc_verify (const PublicKey &pk, const CipherText &c, const EC_POINT *commit,
                                  const CL_ECC_Proof &proof) const;

       /* */
      CL_CL_Proof cl_cl_proof (const PublicKey &pk1, const PublicKey &pk2, const CipherText &c1, const CipherText &c2,
                                  const ClearText &m, const Mpz &r1, const Mpz &r2,
                                  RandGen &randgen) const;
      bool cl_cl_verify (const PublicKey &pk1, const PublicKey &pk2, const CipherText &c1, const CipherText &c2,
                                  const CL_CL_Proof &proof) const;


    protected:
      /* utils for ctor */
      static Mpz random_p (RandGen &randgen, const Mpz &q, size_t DeltaK_nbits);
      static Mpz compute_DeltaK (const Mpz &, const Mpz &);
      static Mpz compute_Delta (const Mpz &, const Mpz &, size_t);
      /* utils */
      void raise_to_power_M (const ClassGroup &Cl, QFI &f) const;
      void F_kerphi_pow (Mpz &, const Mpz &, const Mpz &) const;
      size_t F_kerphi_div (Mpz &, const Mpz &, size_t, const Mpz &) const;
  };

  class CL_HSMqk_ZKAoK : protected CL_HSMqk
  {
    protected:
      size_t C_exp2_; /* Use 2^C_exp2_ as the bound in the ZK proof */
      mutable OpenSSL::HashAlgo H_;

    public:
      using CL_HSMqk::SecretKey;
      using CL_HSMqk::PublicKey;
      using CL_HSMqk::ClearText;
      using CL_HSMqk::CipherText;
      using CL_HSMqk::keygen;
      using CL_HSMqk::encrypt;
      using CL_HSMqk::decrypt;
      using CL_HSMqk::add_ciphertexts;
      using CL_HSMqk::scal_ciphertexts;
      using CL_HSMqk::encrypt_randomness_bound;

      /* ctor */
      CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                                    const Mpz &t);
      CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                                    RandGen &randgen);
      CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, RandGen &randgen);

      class Proof
      {
        protected:
          Mpz u1_;
          Mpz u2_;
          Mpz k_;

        public:
          Proof (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                 const CipherText &c, const ClearText &a, const Mpz &r,
                 RandGen &randgen);

          bool verify (const CL_HSMqk_ZKAoK &, const PublicKey &pk,
                       const CipherText &) const;

        protected:
          Mpz k_from_hash (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                           const CipherText &c, const QFI &t1,
                           const QFI &t2) const;
      };

      /* */
      Proof noninteractive_proof (const PublicKey &pk, const CipherText &c,
                                  const ClearText &a, const Mpz &r,
                                  RandGen &randgen) const;
      bool noninteractive_verify (const PublicKey &pk, const CipherText &c,
                                  const Proof &proof) const;
  };


  #include "CL_HSMqk.inl"

} /* BICYCL namespace */

#endif /* CL_HSM_HPP__ */
