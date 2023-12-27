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
#ifndef THRESHOLD_ECDSA_INL__
#define THRESHOLD_ECDSA_INL__

/******************************************************************************/
/* */
inline
thresholdECDSA::thresholdECDSA (SecLevel seclevel, RandGen &randgen)
  : seclevel_(seclevel), ec_group_ (seclevel_),
    CL_HSMq_ (ec_group_.order(), 1, seclevel_, randgen), H_(seclevel_)
{
}

/* */
inline
const OpenSSL::ECGroup & thresholdECDSA::get_ec_group () const
{
  return ec_group_;
}

/* */
inline
std::tuple<thresholdECDSA::Commitment, thresholdECDSA::Bytes>
thresholdECDSA::commit (OpenSSL::ECPoint::RawSrcPtr Q) const
{
  size_t nbytes = static_cast<unsigned int>(seclevel_) >> 3; /* = seclevel/8 */
  Bytes r(nbytes);
  OpenSSL::random_bytes (r.data(), nbytes);
  OpenSSL::BN x, y;
  ec_group_.get_coords_of_point (x, y, Q);
  Commitment c (H_ (r, x, y));
  return std::make_tuple(c, r);
}

/* */
inline
bool thresholdECDSA::open (const Commitment &c, OpenSSL::ECPoint::RawSrcPtr Q,
                                                const Bytes &r) const
{
  OpenSSL::BN x, y;
  ec_group_.get_coords_of_point (x, y, Q);
  Commitment c2 (H_ (r, x, y));
  return c == c2;
}


#endif /* THRESHOLD_ECDSA_INL__ */
