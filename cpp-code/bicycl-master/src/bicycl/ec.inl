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
#ifndef EC_INL__
#define EC_INL__

/******************************************************************************/
/* */
inline
ECDSA::ECDSA (SecLevel seclevel) : ECGroup(seclevel), H_(seclevel)
{
}

/* */
inline
ECDSA::SecretKey ECDSA::keygen () const
{
  return SecretKey (*this);
}

/* */
inline
ECDSA::PublicKey ECDSA::keygen (const SecretKey &sk) const
{
  return PublicKey (*this, sk.get_ec_point());
}

/* */
inline
void ECDSA::hash_message (OpenSSL::BN &h, const Message &m) const
{
  h.from_bytes (H_ (m));
}

/* */
inline
ECDSA::Signature ECDSA::sign (const SecretKey &sk, const Message &m) const
{
  return Signature (*this, sk, m);
}

/* */
inline
ECDSA::Signature::Signature (const ECDSA &C, const SecretKey &sk,
                                             const Message &m)
{
  OpenSSL::BN z, tmp;

  C.hash_message (z, m);

  do
  {
    SecretKey k (C);
    if (BN_is_zero(k.get_value()))
      continue;

    C.get_x_coord_of_point (tmp, k.get_ec_point());
    C.mod_order (r_, tmp);
    if (r_.is_zero())
      continue;

    C.mul_mod_order (s_, r_, sk.get_value());

    OpenSSL::BN::add (s_, s_, z);

    C.inverse_mod_order (tmp, k.get_value());
    C.mul_mod_order (s_, s_, tmp);
  } while (s_.is_zero());
}

/* */
inline
bool ECDSA::Signature::verify (const ECDSA &C, const PublicKey &Q,
                                               const Message &m) const
{
  OpenSSL::BN z, sinv, u1, u2, x1, tmp;

  if (!C.has_correct_order (Q)) /* check that Q as order n */
    return false;

  if (!C.is_positive_less_than_order (r_))
    return false;

  if (!C.is_positive_less_than_order (s_))
    return false;

  bool ok = true;
  OpenSSL::ECPoint T (C);
  C.hash_message (z, m);
  C.inverse_mod_order (sinv, s_);
  C.mul_mod_order (u1, sinv, z);
  C.mul_mod_order (u2, sinv, r_);

  C.scal_mul (T, u1, u2, Q); /* u1*G + u2*Q */

  if (C.is_at_infinity (T))
    ok = false;
  else
  {
    C.get_x_coord_of_point (tmp, T);
    C.mod_order (x1, tmp);

    ok = (x1 == r_);
  }

  return ok;
}

/* */
inline
bool ECDSA::verif (const Signature &signature, const PublicKey &Q,
                                               const Message &m) const
{
  return signature.verify (*this, Q, m);
}

/* random message of random length between 4 and UCHAR_MAX */
inline
ECDSA::Message ECDSA::random_message () const
{
  unsigned char size;
  OpenSSL::random_bytes (&size, 1 * sizeof (unsigned char));
  size = (size < 4) ? 4 : size;
  Message m (size);
  OpenSSL::random_bytes (m.data(), m.size() * sizeof (unsigned char));
  return m;
}

/******************************************************************************/
/* */
inline
ECNIZK::ECNIZK (SecLevel seclevel) : ECGroup(seclevel), H_(seclevel)
{
}

/* */
inline
ECNIZK::PublicValue ECNIZK::public_value_from_secret (const SecretValue &s) const
{
  return PublicValue (*this, s.get_ec_point());
}

/* */
inline
void ECNIZK::hash_for_challenge (OpenSSL::BN &c, OpenSSL::ECPoint::RawSrcPtr R,
                                 OpenSSL::ECPoint::RawSrcPtr Q) const
{
  OpenSSL::BN xG, yG, xR, yR, xQ, yQ;
  get_coords_of_point (xG, yG, gen());
  get_coords_of_point (xR, yR, R);
  get_coords_of_point (xQ, yQ, Q);

  c.from_bytes (H_ (xG, yG, xR, yR, xQ, yQ));
}

/* */
inline
ECNIZK::Proof ECNIZK::noninteractive_proof (const SecretValue &s) const
{
  return Proof (*this, s);
}

/* */
inline
ECNIZK::Proof::Proof (const ECNIZK &C, const SecretValue &s) : R_(C)
{
  SecretValue r (C);
  R_ = r.get_ec_point();
  OpenSSL::BN tmp;

  C.hash_for_challenge (c_, R_, s.get_ec_point());

  C.mul_mod_order (tmp, c_, s.get_value());
  C.add_mod_order (z_, tmp, r.get_value()); /* z = r + c*s */
}

/* */
inline
bool ECNIZK::noninteractive_verify (const Proof &proof,
                                    const PublicValue &Q) const
{
  return proof.verify (*this, Q);
}

/* */
inline
bool ECNIZK::Proof::verify (const ECNIZK &C, const PublicValue &Q) const
{
  OpenSSL::BN c;
  C.hash_for_challenge (c, R_, Q);

  OpenSSL::ECPoint lhs (C);
  OpenSSL::ECPoint rhs (C);

  C.scal_mul_gen (lhs, z_); /* z*G */

  C.scal_mul (rhs, c, Q);
  C.ec_add (rhs, R_, rhs); /* R + c*Q */

  return c == c_ && C.ec_point_eq (lhs, rhs);
}

#endif /* EC_INL__ */
