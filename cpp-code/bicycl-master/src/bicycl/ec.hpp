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
#ifndef EC_HPP__
#define EC_HPP__

#include "bicycl/seclevel.hpp"
#include "bicycl/gmp_extras.hpp"
#include "bicycl/openssl_wrapper.hpp"

namespace BICYCL
{
  /*****/
  class ECDSA : public OpenSSL::ECGroup
  {
    public:
      using SecretKey = OpenSSL::ECKey;
      using PublicKey = OpenSSL::ECPoint;
      using Message = std::vector<unsigned char>;

      /*** Signature ***/
      class Signature
      {
        public:
          /* constructors */
          Signature (const ECDSA &C, const SecretKey &sk, const Message &m);

          bool verify (const ECDSA &C, const PublicKey &Q,
                                       const Message &m) const;

        private:
          OpenSSL::BN r_, s_;
      };

      /* constructors */
      ECDSA (SecLevel seclevel);

      /* crypto protocol */
      SecretKey keygen () const;
      PublicKey keygen (const SecretKey &sk) const;
      Signature sign (const SecretKey &sk, const Message &m) const;
      bool verif (const Signature &s, const PublicKey &Q,
                                      const Message &m) const;

      /* utils */
      Message random_message () const;

    protected:
      void hash_message (OpenSSL::BN &h, const Message &m) const;

    private:
      mutable OpenSSL::HashAlgo H_;
  }; /* ECDSA */

  /*****/
  class ECNIZK : public OpenSSL::ECGroup
  {
    public:
      using SecretValue = OpenSSL::ECKey;
      using PublicValue = OpenSSL::ECPoint;

      class Proof
      {
        public:
          Proof (const ECNIZK &C, const SecretValue &s);

          bool verify (const ECNIZK &C, const PublicValue &Q) const;

        private:
          OpenSSL::ECPoint R_;
          OpenSSL::BN c_;
          OpenSSL::BN z_;
      };

      /* constructors */
      ECNIZK (SecLevel seclevel);

      PublicValue public_value_from_secret (const SecretValue &s) const;

      /* crypto protocol */
      Proof noninteractive_proof (const SecretValue &s) const;
      bool noninteractive_verify (const Proof &proof,
                                  const PublicValue &Q) const;

    protected:
      /* utils */
      void hash_for_challenge (OpenSSL::BN &c, OpenSSL::ECPoint::RawSrcPtr R,
                                          OpenSSL::ECPoint::RawSrcPtr Q) const;

    private:
      mutable OpenSSL::HashAlgo H_;
  }; /* ECNIZK */

  #include "ec.inl"

} /* BICYCL namespace */

#endif /* EC_HPP__ */
