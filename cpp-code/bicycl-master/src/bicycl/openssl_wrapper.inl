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
#ifndef OPENSSL_WRAPPER_INL__
#define OPENSSL_WRAPPER_INL__

/******************************************************************************/
inline
void random_bytes (unsigned char *buf, int num)
{
  int ret = RAND_bytes (buf, num);
  if (ret != 1)
    throw std::runtime_error ("RAND_bytes failed in random_bytes");
}

/******************************************************************************/
/* */
inline
EVP_MD_CTX * HashAlgo::new_ctx_ ()
{
  EVP_MD_CTX *r = EVP_MD_CTX_new ();
  if (r == NULL)
    throw std::runtime_error ("EVP_MD_CTX_new failed in HashAlgo");
  return r;
}

/* */
inline
HashAlgo::HashAlgo (int nid) : md_(EVP_get_digestbynid (nid)),
                               mdctx_ (new_ctx_())
{
  if (md_ == NULL)
    throw std::runtime_error ("could not set EVP from nid in HashAlgo");
}

/* */
inline
HashAlgo::HashAlgo (SecLevel seclevel) : HashAlgo (seclevel.sha3_openssl_nid())
{
}

/* */
inline
HashAlgo::HashAlgo (const HashAlgo &H) : md_ (H.md_), mdctx_ (new_ctx_())
{
  operator= (H);
}

/* */
inline
HashAlgo::HashAlgo (HashAlgo &&H) : md_ (H.md_), mdctx_ (H.mdctx_)
{
  H.mdctx_ = NULL;
}

/* */
inline
HashAlgo::~HashAlgo ()
{
  EVP_MD_CTX_free (mdctx_);
}

/* */
inline
HashAlgo & HashAlgo::operator= (const HashAlgo &H)
{
  md_ = H.md_;
  int ret = EVP_MD_CTX_copy_ex (mdctx_, H.mdctx_);
  if (ret != 1)
    throw std::runtime_error ("could not copy EVP_MD_CTX");
  return *this;
}

/* */
inline
HashAlgo & HashAlgo::operator= (HashAlgo &&H)
{
  md_ = H.md_;
  mdctx_ = H.mdctx_;
  H.mdctx_ = NULL;
  return *this;
}

/* */
inline
int HashAlgo::digest_size () const
{
  return EVP_MD_size (md_);
}

/* */
template <typename First, typename... Rem>
inline
HashAlgo::Digest HashAlgo::operator() (const First &first, const Rem&... rem)
{
  int ret = EVP_DigestInit_ex (mdctx_, md_, NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestInit_ex failed in HashAlgo");

  Digest h (digest_size ());
  hash_update (first, rem...);

  ret = EVP_DigestFinal_ex (mdctx_, h.data(), NULL);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestFinal_ex failed in HashAlgo");

  return h;
}

/* */
template <typename First, typename... Rem>
inline
void HashAlgo::hash_update (const First &first, const Rem&... rem)
{
  hash_update (first);
  hash_update (rem...);
}

/* */
inline
void HashAlgo::hash_update_implem (const void *ptr, size_t n)
{
  int ret = EVP_DigestUpdate (mdctx_, ptr, n);
  if (ret != 1)
    throw std::runtime_error ("EVP_DigestUpdate failed in hash_update_implem");
}

/* */
template <>
void HashAlgo::hash_update (const std::vector<unsigned char> &m)
{
  hash_update_implem (m.data(), m.size() * sizeof(unsigned char));
}

/* */
template <>
void HashAlgo::hash_update (const Mpz &v)
{
  mpz_srcptr vptr = static_cast<mpz_srcptr> (v);
  hash_update_implem (mpz_limbs_read (vptr), v.nlimbs() * sizeof (mp_limb_t));
}

/******************************************************************************/
/* */
inline
BN::BN () : bn_(BN_new())
{
  if (bn_ == NULL)
    throw std::runtime_error ("could not allocate BIGNUM");
}

/* */
inline
BN::BN (const BN &other) : bn_ (BN_dup (other.bn_))
{
  if (bn_ == NULL)
    throw std::runtime_error ("could not duplicate BIGNUM");
}

/* */
inline
BN::BN (BN &&other) : bn_(other.bn_)
{
  other.bn_ = NULL;
}

/* */
inline
BN & BN::operator= (const BN &other)
{
  const BIGNUM *ret = BN_copy (bn_, other.bn_);
  if (ret == NULL)
    throw std::runtime_error ("could not copy BIGNUM");
  return *this;
}

/* */
inline
BN & BN::operator= (BN &&other)
{
  bn_ = other.bn_;
  other.bn_ = NULL;
  return *this;
}

/* */
inline
BN::~BN ()
{
  BN_free (bn_);
}

/* */
inline
bool BN::operator== (BN::RawSrcPtr other) const
{
  return BN_cmp (bn_, other) == 0;
}

/* */
inline
bool BN::is_zero () const
{
  return BN_is_zero (bn_);
}

/* */
inline
int BN::num_bytes () const
{
  return BN_num_bytes (bn_);
}

/* */
inline
void BN::add (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b)
{
  int ret = BN_add (r.bn_, a, b);
  if (ret != 1)
    throw std::runtime_error ("BN_add failed");
}

/* */
inline
BN::operator BN::RawSrcPtr () const
{
  return bn_;
}

/* */
inline
void BN::to_bytes (std::vector<unsigned char> &dst) const
{
  dst.resize (num_bytes());
  BN_bn2bin (bn_, dst.data());
}

/* */
inline
void BN::from_bytes (const std::vector<unsigned char> &src)
{
  const BIGNUM *ret = BN_bin2bn (src.data(), src.size(), bn_);
  if (ret == NULL)
    throw std::runtime_error ("Could not set BIGNUM from binary");
}

/* */
template <>
void HashAlgo::hash_update (const OpenSSL::BN &v)
{
  std::vector<unsigned char> bin;
  v.to_bytes (bin);
  hash_update (bin);
}

/* */
inline
std::ostream & operator<< (std::ostream &o, const BN &v)
{
  char *buf = BN_bn2dec (v);
  if (buf == NULL)
    throw std::runtime_error ("BN_bn2dec failed in operator<<");
  o << buf;
  OPENSSL_free (buf);
  return o;
}

/****************************************************************************/
/* */
inline
ECPoint::ECPoint (const ECGroup &E) : P_(NULL)
{
  P_ = EC_POINT_new (E.ec_group_);
  if (P_ == NULL)
    throw std::runtime_error ("EC_POINT_new failed in ECPoint constructor");
}

/* */
inline
ECPoint::ECPoint (const ECGroup &E, ECPoint::RawSrcPtr Q) : P_(NULL)
{
  P_ = EC_POINT_dup (Q, E.ec_group_);
  if (P_ == NULL)
    throw std::runtime_error ("EC_POINT_dup failed in ECPoint constructor");
}

/* */
inline
ECPoint::ECPoint (ECPoint &&Q) : P_(Q.P_)
{
  Q.P_ = NULL;
}

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
inline
ECPoint & ECPoint::operator= (ECPoint::RawSrcPtr Q)
{
  int ret = EC_POINT_copy (P_, Q);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_copy failed in ECPoint::operator=");
  return *this;
}

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
inline
ECPoint & ECPoint::operator= (const ECPoint &Q)
{
  return operator= (Q.P_);
}

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
inline
ECPoint & ECPoint::operator= (ECPoint &&Q)
{
  P_ = Q.P_;
  Q.P_ = NULL;
  return *this;
}

/* */
inline
ECPoint::~ECPoint ()
{
  EC_POINT_free (P_);
}

/* */
inline
ECPoint::operator ECPoint::RawSrcPtr  () const
{
  return P_;
}

/******************************************************************************/
/* */
inline
ECKey::ECKey (const ECGroup &E) : key_ (EC_KEY_new())
{
  if (key_ == NULL)
    throw std::runtime_error ("could not allocate EC_KEY in ECKey constructor");

  int ret = EC_KEY_set_group (key_, E.ec_group_);
  if (ret != 1)
    throw std::runtime_error ("could not set group in ECKey constructor");

  ret = EC_KEY_generate_key (key_);
  if (ret != 1)
    throw std::runtime_error ("could not generate key in ECKey constructor");
}

/* */
inline
ECKey::ECKey (const ECKey &K) : key_ (EC_KEY_new())
{
  if (key_ == NULL)
    throw std::runtime_error ("could not allocate EC_KEY in ECKey constructor");

  operator= (K);
}

/* */
inline
ECKey::ECKey (ECKey &&K) : key_(K.key_)
{
  K.key_ = NULL;
}

/* */
inline
ECKey::~ECKey ()
{
  EC_KEY_free (key_);
}

/* */
inline
ECKey & ECKey::operator= (const ECKey &K)
{
  EC_KEY *ret = EC_KEY_copy (key_, K.key_);
  if (ret == NULL)
    throw std::runtime_error ("EC_KEY_copy failed in ECKey copy assignment");
  return *this;
}

/* */
inline
ECKey & ECKey::operator= (ECKey &&K)
{
  key_ = K.key_;
  K.key_ = NULL;
  return *this;
}

/* */
inline
BN::RawSrcPtr ECKey::get_value () const
{
  return EC_KEY_get0_private_key (key_);
}

/* */
inline
ECPoint::RawSrcPtr ECKey::get_ec_point () const
{
  return EC_KEY_get0_public_key (key_);
}

/******************************************************************************/
/* */
inline
ECGroup::ECGroup (SecLevel seclevel) : ctx_ (BN_CTX_new())
{
  int nid = seclevel.elliptic_curve_openssl_nid(); /* openssl curve id */
  ec_group_ = EC_GROUP_new_by_curve_name (nid);
  if (ec_group_ == NULL)
    throw std::runtime_error ("could not allocate elliptic curve");

  if (ctx_ == NULL)
    throw std::runtime_error ("could not allocate BN_CTX");

  order_ = EC_GROUP_get0_order (ec_group_);
}

/* */
inline
ECGroup::ECGroup (ECGroup &&G) : ec_group_ (G.ec_group_),
                                 order_ (std::move(G.order_)),
                                 ctx_ (G.ctx_)
{
  G.ec_group_ = NULL;
  G.ctx_ = NULL;
}

/* */
inline
ECGroup::~ECGroup ()
{
  EC_GROUP_free (ec_group_);
  BN_CTX_free (ctx_);
}

/* */
inline
ECGroup & ECGroup::operator= (ECGroup &&G)
{
  ec_group_ = G.ec_group_;
  G.ec_group_ = NULL;
  ctx_ = G.ctx_;
  G.ctx_ = NULL;
  order_ = std::move (G.order_);
  return *this;
}

/* */
inline
const Mpz & ECGroup::order () const
{
  return order_;
}

/* */
inline
ECPoint::RawSrcPtr ECGroup::gen () const
{
  return EC_GROUP_get0_generator (ec_group_);
}

/* */
inline
bool ECGroup::is_on_curve (ECPoint::RawSrcPtr P) const
{
  return EC_POINT_is_on_curve (ec_group_, P, ctx_);
}

/* */
inline
bool ECGroup::is_at_infinity (ECPoint::RawSrcPtr P) const
{
  return EC_POINT_is_at_infinity (ec_group_, P);
}

/* */
inline
void ECGroup::get_coords_of_point (BN &x, BN &y, ECPoint::RawSrcPtr P) const
{
  int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, y.bn_, ctx_);
  if (ret != 1)
    throw std::runtime_error ("Could not get x, y coordinates");
}

/* */
inline
void ECGroup::get_x_coord_of_point (BN &x, ECPoint::RawSrcPtr P) const
{
  int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, NULL, ctx_);
  if (ret != 1)
    throw std::runtime_error ("Could not get x coordinate");
}

/* */
inline
bool ECGroup::ec_point_eq (ECPoint::RawSrcPtr P, ECPoint::RawSrcPtr Q) const
{
  return EC_POINT_cmp (ec_group_, P, Q, ctx_) == 0;
}

/* */
inline
void ECGroup::ec_add (ECPoint &R, ECPoint::RawSrcPtr P,
                                  ECPoint::RawSrcPtr Q) const
{
  int ret = EC_POINT_add (ec_group_, R.P_, P, Q, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_add failed in add");
}

/* */
inline
void ECGroup::scal_mul_gen (ECPoint &R, BN::RawSrcPtr n) const
{
  int ret = EC_POINT_mul (ec_group_, R.P_, n, NULL, NULL, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul_gen");
}

/* */
inline
void ECGroup::scal_mul (ECPoint &R, BN::RawSrcPtr n,
                                    ECPoint::RawSrcPtr P) const
{
  int ret = EC_POINT_mul (ec_group_, R.P_, NULL, P, n, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
}

/* */
inline
void ECGroup::scal_mul (ECPoint &R, BN::RawSrcPtr m, BN::RawSrcPtr n,
                                                     ECPoint::RawSrcPtr P) const
{
  int ret = EC_POINT_mul (ec_group_, R.P_, m, P, n, ctx_);
  if (ret != 1)
    throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
}

/* We assume that the order is prime (which must be the case for NIST curves) */
inline
bool ECGroup::has_correct_order (ECPoint::RawSrcPtr G) const
{
  if (is_at_infinity (G))
    return false;

  if (!is_on_curve (G))
    return false;

  ECPoint T (*this);

  scal_mul (T, EC_GROUP_get0_order (ec_group_), G);
  return is_at_infinity (T.P_);
}

/* */
inline
void ECGroup::mod_order (BN &r, BN::RawSrcPtr a) const
{
  int ret = BN_nnmod (r.bn_, a, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_nnmod failed");
}

/* */
inline
void ECGroup::add_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const
{
  int ret = BN_mod_add (r.bn_, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_add failed");
}

/* */
inline
void ECGroup::mul_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const
{
  int ret = BN_mod_mul (r.bn_, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
  if (ret != 1)
    throw std::runtime_error ("BN_mod_mul failed");
}

/* */
inline
void ECGroup::inverse_mod_order (BN &r, BN::RawSrcPtr a) const
{
  const BIGNUM *ret = BN_mod_inverse (r.bn_, a, EC_GROUP_get0_order (ec_group_),
                                                ctx_);
  if (ret == NULL)
    throw std::runtime_error ("could not inverse modulo order");
}

/* */
inline
bool ECGroup::is_positive_less_than_order (BN::RawSrcPtr v) const
{
  return !BN_is_negative (v) && !BN_is_zero (v)
                             && BN_cmp (v, EC_GROUP_get0_order (ec_group_)) < 0;
}

#endif /* OPENSSL_WRAPPER_INL__ */
