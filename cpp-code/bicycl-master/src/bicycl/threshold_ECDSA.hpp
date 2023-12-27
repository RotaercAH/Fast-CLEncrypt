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
#ifndef THRESHOLD_ECDSA_HPP__
#define THRESHOLD_ECDSA_HPP__

#include <tuple>

#include "bicycl/gmp_extras.hpp"
#include "bicycl/openssl_wrapper.hpp"
#include "bicycl/ec.hpp"
#include "bicycl/CL_HSMqk.hpp"

namespace BICYCL
{
  /****/
  class thresholdECDSA
  {
    public:
      using Commitment = OpenSSL::HashAlgo::Digest;
      using Bytes = std::vector<unsigned char>;

      /* constructors */
      thresholdECDSA (SecLevel seclevel, RandGen &randgen);

      /* getters */
      const OpenSSL::ECGroup & get_ec_group () const;

      /* utils */
      std::tuple<Commitment, Bytes> commit (OpenSSL::ECPoint::RawSrcPtr Q) const;
      bool open (const Commitment &c, OpenSSL::ECPoint::RawSrcPtr Q,
                                      const Bytes &r) const;

    private:
      const SecLevel seclevel_;
      const OpenSSL::ECGroup ec_group_;
      const CL_HSMqk CL_HSMq_;
      mutable OpenSSL::HashAlgo H_;
  };

  #include "threshold_ECDSA.inl"

} /* BICYCL namespace */

#endif /* THRESHOLD_ECDSA_HPP__ */
