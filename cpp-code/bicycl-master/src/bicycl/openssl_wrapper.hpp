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
#ifndef OPENSSL_WRAPPER_HPP__
#define OPENSSL_WRAPPER_HPP__

#include <iostream>
#include <stdexcept>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h> /* for NID_* */
#include <openssl/rand.h>

#include "bicycl/gmp_extras.hpp"
#include "bicycl/seclevel.hpp"

namespace BICYCL
{
  namespace OpenSSL
  {
    /*****/
    void random_bytes (unsigned char *buf, int num);

    /*****/
    class HashAlgo
    {
      public:
        using Digest = std::vector<unsigned char>;

        static const int SHAKE128 = NID_shake128;
        static const int SHA3_224 = NID_sha3_224;
        static const int SHA3_256 = NID_sha3_256;
        static const int SHA3_384 = NID_sha3_384;
        static const int SHA3_512 = NID_sha3_512;

        /* constructors */
        HashAlgo (SecLevel seclevel); /* Use SHA3 with desired security level */
        HashAlgo (int nid);
        HashAlgo (const HashAlgo &H);
        HashAlgo (HashAlgo &&H);

        /* destructor */
        ~HashAlgo ();

        /* assignment */
        HashAlgo & operator= (const HashAlgo &H);
        HashAlgo & operator= (HashAlgo &&H);

        /* getters */
        int digest_size () const;

        template <typename First, typename... Rem>
        Digest operator() (const First &first, const Rem&... rem);

      protected:
        template <typename First, typename... Rem>
        void hash_update (const First & first, const Rem&... rem);

        void hash_update_implem (const void *ptr, size_t n);

      private:
        static EVP_MD_CTX * new_ctx_ ();

        const EVP_MD *md_;
        EVP_MD_CTX *mdctx_;
    };

    /*****/
    class ECGroup; /* forward declaration */

    /*****/
    class BN
    {
      friend ECGroup;

      public:
        using RawSrcPtr = const BIGNUM *;

        /* constructors */
        BN ();
        BN (const BN &other);
        BN (BN &&other);

        /* destructor */
        ~BN ();

        /* assignment */
        BN & operator= (const BN &other);
        BN & operator= (BN &&other);

        /* comparisons */
        bool operator== (BN::RawSrcPtr other) const;
        bool is_zero () const;

        /* */
        int num_bytes () const;
        static void add (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b);

        /* conversion */
        operator BN::RawSrcPtr () const;
        void to_bytes (std::vector<unsigned char> &dst) const;
        void from_bytes (const std::vector<unsigned char> &src);

        /* */
        friend std::ostream & operator<< (std::ostream &o, const BN &v);

      private:
        BIGNUM *bn_;
    }; /* BN */

    /*****/
    class ECPoint
    {
      friend ECGroup;

      public:
        using RawSrcPtr = const EC_POINT *;

        /* constructors */
        ECPoint (const ECGroup &E);
        ECPoint (const ECGroup &E, ECPoint::RawSrcPtr Q);
        ECPoint (const ECPoint &) = delete;
        ECPoint (ECPoint &&);

        /* assignment */
        ECPoint & operator= (ECPoint::RawSrcPtr Q);
        ECPoint & operator= (const ECPoint &);
        ECPoint & operator= (ECPoint &&);

        /* destructor */
        ~ECPoint ();

        operator ECPoint::RawSrcPtr () const;

      private:
        EC_POINT *P_;
    }; /* ECPoint */

    /*****/
    class ECKey
    {
      friend ECGroup;

      public:
        /* constructors */
        ECKey (const ECGroup &E);
        ECKey (const ECKey &);
        ECKey (ECKey &&);

        /* destructor */
        ~ECKey ();

        /* assignment */
        ECKey & operator= (const ECKey &);
        ECKey & operator= (ECKey &&);

        /* getters */
        BN::RawSrcPtr get_value () const;
        ECPoint::RawSrcPtr get_ec_point () const;

      private:
        EC_KEY *key_;
    }; /* ECKey */

    /****/
    class ECGroup
    {
      /* Constructors of ECPoint and ECKey need to access ec_group_ to create
       * EC_POINT * and EC_KEY *.
       */
      friend ECPoint::ECPoint (const ECGroup &);
      friend ECPoint::ECPoint (const ECGroup &, ECPoint::RawSrcPtr);
      friend ECKey::ECKey (const ECGroup &);

      public:
        static const int P224 = NID_secp224r1;
        static const int P256 = NID_X9_62_prime256v1;
        static const int P384 = NID_secp384r1;
        static const int P521 = NID_secp521r1;

        /* constructors */
        ECGroup (SecLevel seclevel);
        ECGroup (const ECGroup &G) = delete;
        ECGroup (ECGroup &&G);

        /* destructor */
        ~ECGroup ();

        /* assignment */
        ECGroup & operator= (const ECGroup &G) = delete;
        ECGroup & operator= (ECGroup &&G);

        /* getters */
        const Mpz & order () const;

        /* */
        ECPoint::RawSrcPtr gen () const;
        bool is_on_curve (ECPoint::RawSrcPtr P) const;
        bool is_at_infinity (ECPoint::RawSrcPtr P) const;

        /* elliptic operations */
        void get_coords_of_point (BN &x, BN &y, ECPoint::RawSrcPtr P) const;
        void get_x_coord_of_point (BN &x, ECPoint::RawSrcPtr P) const;
        bool ec_point_eq (ECPoint::RawSrcPtr P, ECPoint::RawSrcPtr Q) const;
        void ec_add (ECPoint &R, ECPoint::RawSrcPtr P,
                                 ECPoint::RawSrcPtr Q) const;
        void scal_mul_gen (ECPoint &R, BN::RawSrcPtr n) const;
        void scal_mul (ECPoint &R, BN::RawSrcPtr n,
                                   ECPoint::RawSrcPtr P) const;
        void scal_mul (ECPoint &R, BN::RawSrcPtr m, BN::RawSrcPtr n,
                                                    ECPoint::RawSrcPtr P) const;

        /* arithmetic operations modulo the group order */
        void mod_order (BN &r, BN::RawSrcPtr a) const;
        void add_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const;
        void mul_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const;
        void inverse_mod_order (BN &r, BN::RawSrcPtr a) const;

      protected:
        /* utils */
        bool has_correct_order (ECPoint::RawSrcPtr P) const;
        bool is_positive_less_than_order (BN::RawSrcPtr v) const;

      private:
        EC_GROUP *ec_group_;
        Mpz order_;
        BN_CTX *ctx_;
    }; /* ECGroup */

    #include "openssl_wrapper.inl"

  }; /* namespace OpenSSL */

} /* namespace BICYCL */

#endif /* OPENSSL_WRAPPER_HPP__ */
