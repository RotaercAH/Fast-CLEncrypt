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
#ifndef CL_HSM_INL__
#define CL_HSM_INL__

/**
 * The product \f$ p \times q \f$ must be \f$ 3 \bmod 4 \f$
 *
 * \param[in] q the prime q
 * \param[in] p the prime p or 1
 * \param[in] fud_factor positive integer to use as multiplier for the class
 * number bound
 * \param[in] compact_variant whether the compact variant is used
 *
 */

inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor, const Mpz &M, const QFI &h, const Mpz &exponent_bound, size_t d, const size_t e, const QFI &h_e_precomp, 
                     const QFI &h_d_precomp, const QFI &h_de_precomp, bool compact_variant, bool large_message_variant)
    : q_(q),
      k_(k),
      p_(p),
      Cl_DeltaK_ (compute_DeltaK (q, p)),
      Cl_Delta_ (compute_Delta (Cl_DeltaK_.discriminant(), q, k_)),
      compact_variant_ (compact_variant),
      large_message_variant_(large_message_variant),
      fud_factor_ (fud_factor),
      exponent_bound_(exponent_bound),
      M_(M),
      h_(h),
      d_(d),
      e_(e),
      h_e_precomp_(h_e_precomp),
      h_d_precomp_(h_d_precomp),
      h_de_precomp_(h_de_precomp)
{
}

inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p,
                                  const Mpz &fud_factor, bool compact_variant)
    : q_(q),
      k_(k),
      p_(p),
      Cl_DeltaK_ (compute_DeltaK (q, p)),
      Cl_Delta_ (compute_Delta (Cl_DeltaK_.discriminant(), q, k_)),
      compact_variant_ (compact_variant),
      fud_factor_ (fud_factor)
{
  /* Checks */
  if (q_.sgn() <= 0 || not q_.is_prime())
    throw std::invalid_argument ("q must be a prime");
  if (p_ != 1UL && (p_.sgn() <= 0 || not p_.is_prime()))
    throw std::invalid_argument ("p must be 1 or a prime");
  if ((- p_.mod4() * q_.mod4()) % 4 != 1)
    throw std::invalid_argument ("-p*q mod 4 must be 1");
  if (q_.kronecker (p_) != -1)
    throw std::invalid_argument ("Kronecker symbol of q and p must be -1");
  if (k_ == 0)
    throw std::invalid_argument ("k must be positive");

  /* Compute M = q^k */
  M_ = 1UL;
  for (size_t i = 0; i < k_; i++)
  {
    Mpz::mul (M_, M_, q_);
  }

  /* Assess if we need the large message variant, i.e., if 4*q^(2k) > 1-DeltaK
   */
  Mpz t;
  Mpz::mul (t, M_, M_);       /* t <- M^2 = q^(2*k) */
  Mpz::mulby4 (t, t);         /* t <- 4*q^(2*k) */
  Mpz::sub (t, t, 1UL);       /* t <- 4*q^(2*k) - 1 */
  Mpz::add (t, t, DeltaK());  /* t <- 4*q^(2*k) - 1 + DeltaK  */
  large_message_variant_ = (t.sgn() > 0);

  /* Compute the generator h
   * For the non compact variant, the generator is the square of the
   * smallest primeform of Cl_Delta raised to the power M=q^k.
   * For the compact variant, we push it into Cl_DeltaK and raise it to the
   * power M=q^k.
   */
  /* smallest primeform */
  Mpz l(2UL);
  for ( ; Delta().kronecker (l) != 1; l.nextprime ());
  h_ = Cl_Delta_.primeform (l);

  /* square it */
  Cl_Delta_.nudupl (h_, h_);

  /* raise it to power M=q^k */
  raise_to_power_M (Cl_Delta_, h_);

  if (compact_variant) /* For compact variant, we need \pi(h)^M */
  {
    h_.to_maximal_order (M_, DeltaK());
    raise_to_power_M (Cl_DeltaK_, h_);
  }

  /*
   * Compute the exponent_bound as class_number_bound times fud_factor.
   * If fud_factor is <= 0, the default it to use 2^40.
   */
  exponent_bound_ = Cl_DeltaK_.class_number_bound();
  if (fud_factor_.sgn () <= 0)
  {
    Mpz::mulby2k (exponent_bound_, exponent_bound_, 40);
    Mpz::mulby2k (fud_factor_, 1UL, 40);
  }
  else
    Mpz::mul (exponent_bound_, exponent_bound_, fud_factor_);

  /*
   * Precomputation
   */
  d_ = (encrypt_randomness_bound().nbits () + 1)/2;
  e_ = d_/2 + 1;
  h_de_precomp_ = h_;
  for (size_t i = 0; i < d_+e_; i++)
  {
    if (i == e_)
      h_e_precomp_ = h_de_precomp_;
    if (i == d_)
      h_d_precomp_ = h_de_precomp_;
    Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
  }
}

/**
 */
inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p,
                                            const Mpz &fud_factor)
  : CL_HSMqk (q, k, p, fud_factor, false)
{
}

/**
 */
inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, bool compact_variant)
  : CL_HSMqk (q, k, p, Mpz(0UL), compact_variant)
{
}

/**
 */
inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p)
  : CL_HSMqk (q, k, p, Mpz(0UL))
{
}

/**
 */
inline
CL_HSMqk::CL_HSMqk (const CL_HSMqk &C, bool compact_variant)
  : CL_HSMqk (C)
{
  if (compact_variant != C.compact_variant_)
  {
    compact_variant_ = compact_variant;
    if (compact_variant)
    {
      /* we go from non compact to compact variant, we need to compute
       * \pi(h)^M
       */
      h_.to_maximal_order (M_, DeltaK());
      raise_to_power_M (Cl_DeltaK_, h_);
    }
    else
    {
      /* smallest primeform */
      Mpz l(2UL);
      for ( ; Delta().kronecker (l) != 1; l.nextprime ());
      h_ = Cl_Delta_.primeform (l);

      /* square it */
      Cl_Delta_.nudupl (h_, h_);

      /* raise it to power M=q^k */
      raise_to_power_M (Cl_Delta_, h_);
    }


    /* precomputations */
    h_de_precomp_ = h_;
    for (size_t i = 0; i < d_+e_; i++)
    {
      if (i == e_)
        h_e_precomp_ = h_de_precomp_;
      if (i == d_)
        h_d_precomp_ = h_de_precomp_;
      Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
    }
  }
}

/**
 * @private
 */
template <class... Ts>
inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, size_t DeltaK_nbits,
                                            RandGen &randgen, Ts... args)
  : CL_HSMqk (q, k, CL_HSMqk::random_p (randgen, q, DeltaK_nbits), args...)
{
}

/**
 * @private
 */
template <class... Ts>
inline
CL_HSMqk::CL_HSMqk (size_t q_nbits, size_t k, size_t DeltaK_nbits,
                                              RandGen &randgen, Ts... args)
  : CL_HSMqk (randgen.random_prime (q_nbits), k, DeltaK_nbits, randgen, args...)
{
}

/**
 * @private
 */
template <class... Ts>
inline
CL_HSMqk::CL_HSMqk (size_t q_nbits, size_t k, SecLevel seclevel,
                                              RandGen &randgen, Ts... args)
  : CL_HSMqk (randgen.random_prime(q_nbits), k, seclevel, randgen, args...)
{
  if (q_nbits < seclevel)
    throw std::invalid_argument ("Number of bits of q should not be smaller "
                                 "than the security level");
}

/**
 * @private
 */
template <class... Ts>
inline
CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, SecLevel seclevel, RandGen &randgen,
                                                     Ts... args)
  : CL_HSMqk (q, k, seclevel.discriminant_bitsize(), randgen, args...)
{
  if (q.nbits() < seclevel)
    throw std::invalid_argument ("Number of bits of q should not be smaller "
                                 "than the security level");
}

/* */
inline
const Mpz & CL_HSMqk::q () const
{
  return q_;
}

/* */
inline
size_t CL_HSMqk::k () const
{
  return k_;
}

/* */
inline
size_t CL_HSMqk::e () const
{
  return e_;
}

/* */
inline
size_t CL_HSMqk::d () const
{
  return d_;
}


/* */
inline
const Mpz & CL_HSMqk::p () const
{
  return p_;
}

/* */
inline
const Mpz & CL_HSMqk::M () const
{
  return M_;
}

/* */
inline
const Mpz & CL_HSMqk::fud_factor () const
{
  return fud_factor_;
}

/* */
inline
const ClassGroup & CL_HSMqk::Cl_DeltaK () const
{
  return Cl_DeltaK_;
}

/* */
inline
const ClassGroup & CL_HSMqk::Cl_Delta () const
{
  return Cl_Delta_;
}

/* */
inline
const ClassGroup & CL_HSMqk::Cl_G () const
{
  return compact_variant_ ? Cl_DeltaK_ : Cl_Delta_;
}

/* */
inline
const Mpz & CL_HSMqk::DeltaK () const
{
  return Cl_DeltaK_.discriminant();
}

/* */
inline
const Mpz & CL_HSMqk::Delta () const
{
  return Cl_Delta_.discriminant();
}

/* */
inline
const QFI & CL_HSMqk::h () const
{
  return h_;
}

/* */
inline
const QFI & CL_HSMqk::h_e_precomp () const
{
  return h_e_precomp_;
}

/* */
inline
const QFI & CL_HSMqk::h_d_precomp () const
{
  return h_d_precomp_;
}

/* */
inline
const QFI & CL_HSMqk::h_de_precomp () const
{
  return h_de_precomp_;
}

/* */
inline
bool CL_HSMqk::compact_variant () const
{
  return compact_variant_;
}

/* */
inline
bool CL_HSMqk::large_message_variant () const
{
  return large_message_variant_;
}

/* */
inline
std::ostream & operator<< (std::ostream &o, const CL_HSMqk &C)
{
  return o << "q = " << C.q() << " # " << C.q().nbits() << " bits" << std::endl
           << "k = " << C.k() << std::endl
           << "p = " << C.p() << " # " << C.p().nbits() << " bits" << std::endl
           << "DeltaK = -p*q # " << C.DeltaK().nbits() << " bits" << std::endl
           << "Delta = -p*q^(2*k+1) # " << C.Delta().nbits() << " bits" << std::endl
           << "h = " << C.h() << std::endl
           << "compact_variant = " << C.compact_variant() << std::endl
           << "large_message_variant = " << C.large_message_variant()
           << std::endl;
}

/* */
inline
const Mpz & CL_HSMqk::secretkey_bound () const
{
  return exponent_bound_;
}

/* */
inline
const Mpz & CL_HSMqk::cleartext_bound () const
{
  return M_;
}

/* */
inline
const Mpz & CL_HSMqk::encrypt_randomness_bound () const
{
  return exponent_bound_;
}

/**
 * \param[out] r the quadratic form corresponding to #gen to the power of \p e
 * \param[in] e the exponent
 */
inline
void CL_HSMqk::power_of_h (QFI &r, const Mpz &n) const
{
  Cl_G().nupow (r, h_, n, d_, e_, h_e_precomp_, h_d_precomp_,
                                                    h_de_precomp_);
}

/*
 * Return f^m where f is the form [ q^(2k), q^k, .. ] of discriminant
 * -p*q^(2k+1).
 *
 * Input:
 *  m: integer
 *
 * - Case k == 1: for m != 0 modulo q, f^m is the form [ q^2, L(m)*q, ... ]
 * of discriminant -p*q^3 where L(m) is a odd representative of 1/m modulo q in
 * [-q, q].  This form is reduced if p > 4*q. For m == 0 modulo q,
 * f^m is the principal form [ 1, 1, (1+p*q^3)/4 ] of discriminant -p*q^3.
 * - Case k > 1:
 */
inline
QFI CL_HSMqk::power_of_f (const Mpz &m) const
{
  if (k_ == 1)
  {
    /* Note: c is used as temporary variable to store L(m) */
    Mpz a, b, c;

    try
    {
      Mpz::mod_inverse (c, m, q_);
      if (c.is_even ())
        Mpz::sub (c, c, q_);
      /*    [ q^2, Lm*q, ((Lm*q)^2-Delta_q)/(4*q^2) ]
       * =  [ q^2, Lm*q, ((Lm*q)^2-q^2*Delta_K)/(4*q^2) ]
       * =  [ q^2, Lm*q, (Lm^2-Delta_K)/4 ]
       */
      Mpz::mul (a, q_, q_); /* a = q^2 */
      Mpz::mul (b, c, q_); /* b = Lm*q */
      Mpz::mul (c, c, c);
      Mpz::sub (c, c, DeltaK());
      Mpz::divby4 (c, c); /* c = (Lm^2-Delta_K)/4 */
      /* No need to check the form (a,b,c)
       * But, for large_message variant, the form is not necessarily reduced.
       */
      return QFI (a, b, c, true);
    }
    catch (Mpz::ModInverseException &e)
    {
      /* if m is not invertible, set the form to the principal form */
      return Cl_Delta_.one();
    }
  }
  else /* k_ > 1 */
  {
    Mpz n;
    Mpz::mod (n, m, M_); /* n = m % M=2^k */

    if (n.sgn() == 0) /* m == 0 mod 2^k */
    {
      return Cl_Delta_.one();
    }
    else /* m != 0 mod 2^k: compute Lucas chains U_n and V_n */
    {
      /* Lucas chains with P=1 and Q=(1-DeltaK)/4 (so D = P^2 - 4*Q = DeltaK)
       * Computing U_n and V_n can be done by computing
       *  (0  1)^n (U0)         (0  1)^n (V0)
       *  (-Q P)   (U1)   and   (-Q P)   (V1)
       * Note that U0 = 0, U1 = 1, V0 = 2 and V1 = P = 1.
       */
      /* TODO maybe faster using direct formula with binomials for Un and Vn.
       * Bench it to compare.
       */
      Mpz m00(1UL), m01(0UL);
      Mpz m10(0UL), m11(1UL);
      Mpz minusQ, t0, t1, t2, t3;

      Mpz::sub (minusQ, DeltaK(), 1UL);
      Mpz::divby4 (minusQ, minusQ);

      for (size_t i = n.nbits(); i > 0; i--)
      {
        /* square */
        Mpz::mul (t0, m00, m00);
        Mpz::addmul (t0, m01, m10);
        Mpz::mod (t0, t0, M_);

        Mpz::mul (t1, m00, m01);
        Mpz::addmul (t1, m01, m11);
        Mpz::mod (t1, t1, M_);

        Mpz::mul (t2, m10, m00);
        Mpz::addmul (t2, m11, m10);
        Mpz::mod (t2, t2, M_);

        Mpz::mul (t3, m10, m01);
        Mpz::addmul (t3, m11, m11);
        Mpz::mod (t3, t3, M_);

        Mpz::swap (m00, t0);
        Mpz::swap (m01, t1);
        Mpz::swap (m10, t2);
        Mpz::swap (m11, t3);

        /* mul */
        if (n.tstbit (i-1))
        {
          Mpz::mul (m00, m00, minusQ);
          Mpz::add (m00, m00, m10);
          Mpz::mod (m00, m00, M_);

          Mpz::mul (m01, m01, minusQ);
          Mpz::add (m01, m01, m11);
          Mpz::mod (m01, m01, M_);

          Mpz::swap (m00, m10);
          Mpz::swap (m01, m11);
        }
      }

      /* Vn = 2*m00+m01 */
      Mpz::add (t0, m00, m01);
      Mpz::add (t0, t0, m00);

      /* Un = m01, we need Un/q^(k-j) = Un/q^valq */
      const size_t valq = Mpz::remove (t1, m01, q_);

      t3 = 1UL;
      for (size_t i = 0; i < k_-valq; i++)
      {
        Mpz::mul (t3, t3, q_);
      }
      /* now t3 = q^(k-valq) = q^j */
      Mpz::mod_inverse (t2, t1, t3); /* t2 <- (Un/q^(k-j))^1 mod q^j */

      Mpz::mul (t0, t0, t2);
      Mpz::mod (t0, t0, t3);
      if (t0.is_even()) /* if even, substract q^j */
        Mpz::sub (t0, t0, t3);

      /* a <- q^(2*(k-valq)) = q^(2*j) = (q^j)^2    [ stored in t1 ] */
      Mpz::mul (t1, t3, t3);
      /* b <- q^(k-valq) * u  [ stored in t2 ] */
      Mpz::mul (t2, t0, t3);
      /* c <- (u^2 - q^(2*valq)*Delta_K)/4  [ stored in t3 ] */
      t3 = 1UL;
      for (size_t i = 0; i < valq; Mpz::mul (t3, t3, q_), i++);
      Mpz::mul (t3, t3, t3);        /* q^(2*valq) */
      Mpz::mul (t3, t3, DeltaK());  /* q^(2*valq) * Delta_K */
      Mpz::submul (t3, t0, t0);     /* q^(2*valq) * Delta_K - u^2 */
      t3.neg();
      Mpz::divby4 (t3, t3);

      /* No need to check the form (a,b,c) */
      return QFI (t1, t2, t3, true);
    }
  }
}

/* Assume fm is in F */
inline
Mpz CL_HSMqk::dlog_in_F (const QFI &fm) const
{
  Mpz m;
  if (!fm.is_one ())
  {
    Mpz tmp, tm;
    size_t tm_valq;
    /* tm = tm*q^tm_valq */

    if (large_message_variant_)
    {
      tm = fm.kernel_representative (M_, DeltaK());
      tm_valq = Mpz::remove (tm, tm, q_);
    }
    else
    {
      Mpz u;
      size_t j = Mpz::remove (u, fm.b(), q_); /* j, u such that ft.b = q^j*u */
      /* tm = q^(k-j)*1/u mod M=q^k */
      Mpz::mod_inverse (tm, u, M_);
      tm_valq = k_ - j;
    }

    if (k_ == 1) /* easy case */
    {
      m = tm;
    }
    else
    {
      Mpz mi, t(1UL), qe(1UL);

      for (size_t i = 0; i < k_; i++)
      {
        if (tm_valq == i)
        {
          Mpz::mod (mi, tm, q_);
          F_kerphi_pow (tmp, t, mi);
          tm_valq = F_kerphi_div (tm, tm, tm_valq, tmp);
        }
        else
        {
          mi = 0UL;
        }
        Mpz::addmul (m, mi, qe);
        Mpz::mul (qe, qe, q_);
        F_kerphi_pow (t, t, q_);
      }
    }
  }
  /* else: m is already set to the correct value: 0 */
  return m;
}

/* */
inline
void CL_HSMqk::from_Cl_DeltaK_to_Cl_Delta (QFI &f) const
{
  f.lift (M_);
  raise_to_power_M (Cl_Delta_, f);
}

/* */
inline
CL_HSMqk::SecretKey CL_HSMqk::keygen (RandGen &randgen) const
{
  return SecretKey (*this, randgen);
}

/* */
inline
CL_HSMqk::SecretKey CL_HSMqk::keygen (Mpz &sk) const
{
  return SecretKey (*this, sk);
}

/* */
inline
CL_HSMqk::PublicKey CL_HSMqk::keygen (const SecretKey &sk) const
{
  return PublicKey (*this, sk);
}

/* */
inline
CL_HSMqk::PublicKey CL_HSMqk::keygen (const QFI &pk) const
{
  return PublicKey (*this, pk);
}

/*
 * Encrypt the plaintext using the cryptosystems described by params, the
 * public key pk and the randomness r.
 *
 * Input:
 *  params: the parameters of the cryptosystems
 *  pk: the public key
 *  m: the plaintext to encrypt
 *  r: randomness
 */
inline
CL_HSMqk::CipherText CL_HSMqk::encrypt (const PublicKey &pk, const ClearText &m,
                              const Mpz &r) const
{
  return CipherText (*this, pk, m, r);
}


/*
 * Same as above but without the randomness
 */
inline
CL_HSMqk::CipherText CL_HSMqk::encrypt (const PublicKey &pk, const ClearText &m,
                              RandGen &randgen) const
{
  return encrypt (pk, m, randgen.random_mpz (encrypt_randomness_bound()));
}

/*
 * Decrypt the ciphertext c using the cryptosystems described by params and
 * the secret key sk
 *
 * Input:
 *  sk: the secret key
 *  c: the ciphertext
 */
inline
CL_HSMqk::ClearText CL_HSMqk::decrypt (const SecretKey &sk, const CipherText &c)
                                                                          const
{
  return ClearText (*this, sk, c);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::add_ciphertexts (const PublicKey &pk,
                                                const CipherText &ca,
                                                const CipherText &cb,
                                                RandGen &randgen) const
{
  Mpz r(randgen.random_mpz (encrypt_randomness_bound()));
  return add_ciphertexts (pk, ca, cb, r);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::add_ciphertexts (const PublicKey &pk,
                                                const CipherText &ca,
                                                const CipherText &cb,
                                                const Mpz &r) const
{
  return CipherText (*this, pk, ca, cb, r);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::add_ciphertexts (const CipherText &ca,
                                                const CipherText &cb) const
{
  return CipherText (*this, ca, cb);
}

/* */
inline
CL_HSMqk::ClearText CL_HSMqk::add_cleartexts (const ClearText &ma,
                                              const ClearText &mb) const
{
  return ClearText (*this, ma, mb);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::scal_ciphertexts (const PublicKey &pk,
                                                 const CipherText &c,
                                                 const Mpz &s,
                                                 RandGen &randgen) const
{
  Mpz r(randgen.random_mpz (encrypt_randomness_bound()));
  return scal_ciphertexts (pk, c, s, r);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::scal_ciphertexts (const PublicKey &pk,
                                                 const CipherText &c,
                                                 const Mpz &s,
                                                 const Mpz &r) const
{
  return CipherText (*this, pk, c, s, r);
}

/* */
inline
CL_HSMqk::CipherText CL_HSMqk::scal_ciphertexts (const CipherText &c,
                                                 const Mpz &s) const
{
  return CipherText (*this, c, s);
}

/* */
inline
CL_HSMqk::ClearText CL_HSMqk::scal_cleartexts (const ClearText &m, const Mpz &s)
                                                                          const
{
  return ClearText (*this, m, s);
}

/*
 * Assumes q is a prime
 */
inline
Mpz CL_HSMqk::random_p (RandGen &randgen, const Mpz &q, size_t DeltaK_nbits)
{
  Mpz p;

  /* The product -p*q must be 1 mod 4 (<=> p*q must be 3 mod 4)
   * As p and q are odd, it means that they must be different mod 4.
   */
  unsigned long pmod4_target = q.mod4() == 3UL ? 1UL : 3UL;

  size_t pbits = q.nbits() < DeltaK_nbits ? DeltaK_nbits - q.nbits() : 0;

  /* Generate a random prime p satisfying the conditions */
  if (pbits == 0)
    p = 1UL;
  else if (pbits == 1)
    p = 3UL;
  else
    p = randgen.random_prime (pbits);
  while (p.mod4() != pmod4_target || q.kronecker (p) != -1)
  {
    p.nextprime ();
  }

  return p;
}

/* Compute DeltaK = -p*q
 */
inline
Mpz CL_HSMqk::compute_DeltaK (const Mpz &q, const Mpz &p)
{
  Mpz d;
  Mpz::mul (d, p, q);
  d.neg ();
  return d;
}

/* Compute Delta = q^(2*k) * DeltaK = -p*q^(2*k+1)
 */
inline
Mpz CL_HSMqk::compute_Delta (const Mpz &DeltaK, const Mpz &q, size_t k)
{
  Mpz q2;
  Mpz::mul (q2, q, q);
  Mpz d(DeltaK);
  for (size_t i = 0; i < k; i++)
  {
    Mpz::mul (d, d, q2);
  }
  return d;
}

/* */
inline
void CL_HSMqk::raise_to_power_M (const ClassGroup &Cl, QFI &f) const
{
  Cl.nupow (f, f, M_);
}

/*
 * Compute (1+t*sqrt(DeltaK))^n in (OK/q^k OK)* / (Z/q^k Z)*
 * Result is given as (1+r*sqrt(DeltaK))
 * Use double and add to perform exponentiation
 */
inline
void CL_HSMqk::F_kerphi_pow (Mpz &r, const Mpz &t, const Mpz &n) const
{
  Mpz a(1UL), b(0UL), tmp;

  for (size_t i = n.nbits(); i > 0; i--)
  {
    /* square */
    Mpz::mul (tmp, a, b);
    Mpz::mulby2 (tmp, tmp);
    Mpz::mod (tmp, tmp, M_);

    Mpz::mul (a, a, a);
    Mpz::mul (b, b, b);
    Mpz::addmul (a, b, Cl_DeltaK_.discriminant());
    Mpz::mod (a, a, M_);

    Mpz::swap (tmp, b);

    /* mul */
    if (n.tstbit (i-1))
    {
      Mpz::mul (tmp, b, t);
      Mpz::addmul (b, a, t);
      Mpz::mod (b, b, M_);

      Mpz::addmul (a, tmp, Cl_DeltaK_.discriminant());
      Mpz::mod (a, a, M_);
    }
  }

  Mpz::mod_inverse (r, a, M_);
  Mpz::mul (r, r, b);
  Mpz::mod (r, r, M_);

}

/*
 * Compute (1+t*q^v*sqrt(DeltaK))/(1+s*sqrt(DeltaK)) in
 *  (OK/q^k OK)* / (Z/q^k Z)*
 * Result is given as (1+r*q^(return value)*sqrt(DeltaK))
 */
inline
size_t CL_HSMqk::F_kerphi_div (Mpz &r, const Mpz &t, size_t v, const Mpz &s)
                                                                          const
{
  Mpz tmp0, tmp1;

  Mpz::mul (tmp0, t, s);
  for (size_t i = 0; i < v; i++)
  {
    Mpz::mul (tmp0, tmp0, q_);
  }

  Mpz::mul (tmp0, tmp0, Cl_DeltaK_.discriminant());
  tmp0.neg();
  Mpz::add (tmp0, tmp0, 1UL);
  Mpz::mod_inverse (tmp0, tmp0, M_);

  size_t j = Mpz::remove (tmp1, s, q_);
  if (j < v)
  {
    r = t;
    for (size_t i = 0; i < v-j; i++)
    {
      Mpz::mul (r, r, q_);
    }
    Mpz::sub (r, r, tmp1);
  }
  else if (j > v)
  {
    for (size_t i = 0; i < j-v; i++)
    {
      Mpz::mul (tmp1, tmp1, q_);
    }
    Mpz::sub (r, r, tmp1);
    j = v;
  }
  else /* j == v */
  {
    Mpz::sub (r, t, tmp1);
    j = v + Mpz::remove (r, r, q_);
  }
  Mpz::mul (r, r, tmp0);
  Mpz::mod (r, r, M_);
  return j;
}

/**
 *
 * Remark:
 *  - chi_p and chi_q can be computed using different evaluations
 *  - At least on of f(1,0) = a, f(0,1) = c and f(1,1) = a+b+c is coprime with p
 *  (resp. q). Note that the evaluation used to compute chi_p and chi_q could be
 *  different.
 */
inline
CL_HSMqk::Genus CL_HSMqk::genus (const QFI &f) const
{
  int chi_q, chi_p;
  chi_q = f.a().jacobi (q_);
  if (chi_q == 0)
    chi_q = f.c().jacobi (q_);

  chi_p = f.a().jacobi (p_);
  if (chi_p == 0)
    chi_p = f.c().jacobi (p_);

  if (chi_p == 0 || chi_q == 0)
  {
    Mpz t;
    Mpz::add (t, f.a(), f.b());
    Mpz::add (t, t, f.c());
    if (chi_q == 0)
      chi_q = t.jacobi (q_);
    if (chi_p == 0)
      chi_p = t.jacobi (p_);
  }
  return { chi_q, chi_p };
}

/* */
inline
CL_HSMqk::CL_ECC_Proof CL_HSMqk::cl_ecc_proof (const PublicKey &pk,
                                                            const CipherText &c,
                                                            const EC_POINT *commit,
                                                            const ClearText &m,
                                                            const Mpz &r,
                                                            RandGen &randgen)
                                                            const
{
  return CL_ECC_Proof (*this, pk, c, commit, m, r, randgen);
}

/* */
inline
bool CL_HSMqk::cl_ecc_verify (const PublicKey &pk,
                                            const CipherText &c,
                                            const EC_POINT *commit,
                                            const CL_ECC_Proof &proof) const
{
  return proof.CL_ECC_verify (*this, pk, c, commit);
}

/* */
CL_HSMqk::CL_ECC_Proof::CL_ECC_Proof (const CL_HSMqk &C, const PublicKey &pk,
                              const CipherText &c, const EC_POINT *commit, const ClearText &m,
                              const Mpz &r, RandGen &randgen)
{
  Mpz B (C.exponent_bound_);
  Mpz::mul (B, B, C.fud_factor_);

  BN_CTX *ctx = BN_CTX_new();
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  const EC_POINT *G = EC_GROUP_get0_generator (group);
  
  Mpz sr (randgen.random_mpz (B));
  Mpz sm (randgen.random_mpz (C.M_));
  BIGNUM* sm_bn = BN_new();
  BN_dec2bn(&sm_bn, sm.tostring().c_str());

  EC_POINT *T = EC_POINT_new(group);
  EC_POINT_mul(group, T, NULL, G, sm_bn, ctx); // T = sm * G
  CipherText t (C.encrypt (pk, ClearText (C, sm), sr));

  /* Generate k using hash function */
  e_ = generate_hash (C, pk, c, T, t.c1(), t.c2());
  Mpz::mod (e_, e_, C.exponent_bound_);

  Mpz::mul (zr_, e_, r);
  Mpz::add (zr_, zr_, sr);

  Mpz::mul (zm_, e_, m);
  Mpz::add (zm_, zm_, sm);
  Mpz::mod (zm_, zm_, C.M_);
}

/* */
bool CL_HSMqk::CL_ECC_Proof::CL_ECC_verify (const CL_HSMqk &C,
                                    const PublicKey &pk, 
                                    const CipherText &c, const EC_POINT *commit) const
{
  bool ret = true;

  /* Check that pk is a form in G */
  ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (pk.elt()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c1 is a form in G */
  ret &= c.c1().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (c.c1()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c2 */
  ret &= c.c2().discriminant() == C.Cl_Delta().discriminant();
  ret &= C.genus (c.c2()) == CL_HSMqk::Genus ({ 1, 1 });
  
  /* Check zr bound */
  Mpz B (C.fud_factor_);
  Mpz::add (B, B, 1UL);
  Mpz::mul (B, B, C.exponent_bound_);
  Mpz::mul (B, B, C.exponent_bound_);
  ret &= (zr_.sgn() >= 0 && zr_ <= B);
  /* Check zm bound */
  ret &= (zm_.sgn() >= 0 && zm_ < C.M_);
  /* cu = (gq^zr, pk^zr f^zm) */
  CipherText cu (C.encrypt (pk, ClearText (C, zm_), zr_));

  /* ck = (c1^e, c2^e) */
  CipherText ck (C.scal_ciphertexts (pk, c, e_, Mpz (0UL)));

  BN_CTX *ctx = BN_CTX_new();
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  const EC_POINT *G = EC_GROUP_get0_generator (group);

  EC_POINT *T =  EC_POINT_new(group);
  QFI t1, t2;

   /* Using the equality zm * G == T + commit * k to compute T */
  BIGNUM* zm_bn = BN_new();
  BIGNUM* e_bn = BN_new();
  BN_dec2bn(&zm_bn, zm_.tostring().c_str());
  BN_dec2bn(&e_bn, e_.tostring().c_str());

  EC_POINT_mul(group, T, NULL, G, zm_bn, ctx); // zm * G

  BIGNUM* neg_one = BN_new();
  BN_one(neg_one);
  BN_set_negative(neg_one, 1);

  EC_POINT* neg_commit = EC_POINT_new(group);

  EC_POINT_mul(group, neg_commit, NULL, commit, neg_one, ctx);
  EC_POINT_mul(group, neg_commit, NULL, neg_commit, e_bn, ctx);
  EC_POINT_add(group, T, T, neg_commit, ctx);

  /* Using the equality gq^zr == t1*c1^e to compute t1 */
  C.Cl_G().nucompinv (t1, cu.c1(), ck.c1());

  /* Using the equality pk^zr f^zm == t2*c2^e to compute t2 */
  C.Cl_Delta().nucompinv (t2, cu.c2(), ck.c2());

  /* Generate e using hash function and check that it matches */
  Mpz e (generate_hash (C, pk, c, T, t1, t2));
  Mpz::mod (e, e, C.exponent_bound_);

  ret &= (e == e_);
  return ret;
}

/* */
inline
CL_HSMqk::CL_ECC_Proof::CL_ECC_Proof(const Mpz zm, const Mpz zr, const Mpz e) : zm_(zm), zr_(zr), e_(e) {}

/* */
std::string CL_HSMqk::CL_ECC_Proof::cl_ecc_toString () const {
  return zm_.tostring() + " " + zr_.tostring() + " " + e_.tostring();
}


std::string qfi2string(const QFI &qfi){
    auto qfi_comp = qfi.compressed_repr();
    const std::string is_neg = (qfi_comp.is_neg) ? "true" : "false";
    auto out = qfi_comp.ap.tostring() + " " + qfi_comp.g.tostring() + " " + qfi_comp.tp.tostring() + " " + qfi_comp.b0.tostring() + " " + is_neg + " " + qfi.discriminant().tostring();
    return out;
}

/* */
inline
Mpz CL_HSMqk::CL_ECC_Proof::generate_hash (const CL_HSMqk &C,
                                        const PublicKey &pk,
                                        const CipherText &c, const EC_POINT *T,
                                        const QFI &t1, const QFI &t2) const
{
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    std::string pk_str = qfi2string(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi2string(pk.e_precomp()) + ":" + qfi2string(pk.d_precomp()) + ":" + qfi2string(pk.de_precomp());
    std::string c_str = qfi2string(c.c1()) + qfi2string(c.c2());
    auto T_str = EC_POINT_point2hex(group, T, POINT_CONVERSION_COMPRESSED, ctx);
    auto input = pk_str + c_str + T_str + qfi2string(t1) + qfi2string(t2);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    BIGNUM *res = BN_new();
    BN_hex2bn(&res, ss.str().c_str());
    return Mpz (BN_bn2dec(res));
}

/* */
inline
CL_HSMqk::CL_Enc_Com_Proof CL_HSMqk::cl_enc_com_proof (const CL_HSMqk &C_dkg,    
                                                            const PublicKey &pk,
                                                            const CipherText &c,
                                                            const QFI &com,
                                                            const ClearText &m,
                                                            const Mpz &r,
                                                            RandGen &randgen)
                                                            const
{
  return CL_Enc_Com_Proof (*this, C_dkg, pk, c, com, m, r, randgen);
}

/* */
inline
bool CL_HSMqk::cl_enc_com_verify (const CL_HSMqk &C_dkg,        
                                            const PublicKey &pk,
                                            const CipherText &c,
                                            const QFI &com,
                                            const CL_Enc_Com_Proof &proof) const
{
  return proof.CL_Enc_Com_verify (*this, C_dkg, pk, c, com);
}

/* */
CL_HSMqk::CL_Enc_Com_Proof::CL_Enc_Com_Proof (const CL_HSMqk &C, const CL_HSMqk &C_dkg, const PublicKey &pk,
                              const CipherText &c, const QFI &com, const ClearText &m,
                              const Mpz &r, RandGen &randgen)
{
  Mpz B (C.exponent_bound_);
  Mpz::mul (B, B, C.fud_factor_);
  
  Mpz sr (randgen.random_mpz (B));
  Mpz sm (randgen.random_mpz (C.M_));
  QFI T;
  CipherText t (C.encrypt (pk, ClearText (C, sm), sr));
  C_dkg.power_of_h(T, sm);
  /* Generate k using hash function */
  e_ = generate_hash (C, pk, c, com, t.c1(), t.c2(), T);
  Mpz::mod (e_, e_, C.exponent_bound_);

  Mpz::mul (zr_, e_, r);
  Mpz::add (zr_, zr_, sr);

  Mpz::mul (zm_, e_, m);
  Mpz::add (zm_, zm_, sm);
  // Mpz::mod (zm_, zm_, C.M_);
}

/* */
bool CL_HSMqk::CL_Enc_Com_Proof::CL_Enc_Com_verify (const CL_HSMqk &C, const CL_HSMqk &C_dkg,
                                    const PublicKey &pk, const CipherText &c,  const QFI &com) const
{
  bool ret = true;

  /* Check that pk is a form in G */
  ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (pk.elt()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c1 is a form in G */
  ret &= c.c1().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (c.c1()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c2 */
  ret &= c.c2().discriminant() == C.Cl_Delta().discriminant();
  ret &= C.genus (c.c2()) == CL_HSMqk::Genus ({ 1, 1 });
  /* Check zr bound */
  Mpz B (C.fud_factor_);
  Mpz::add (B, B, 1UL);
  Mpz::mul (B, B, C.exponent_bound_);
  Mpz::mul (B, B, C.exponent_bound_);
  ret &= (zr_.sgn() >= 0 && zr_ <= B);
  /* Check zm bound */
  // ret &= (zm_.sgn() >= 0 && zm_ < C.M_);
  /* cu = (gq^zr, pk^zr f^zm) */
  Mpz zm_mod;
  Mpz::mod (zm_mod, zm_, C.M_);
  CipherText cu (C.encrypt (pk, ClearText (C, zm_mod), zr_));

  /* ck = (c1^e, c2^e) */
  CipherText ck (C.scal_ciphertexts (pk, c, e_, Mpz (0UL)));

  QFI comu, comk;
  /* comu =  gq^zm*/
  C_dkg.power_of_h(comu, zm_);
  /* comk = com^e */
  C_dkg.Cl_G().nupow(comk, com, e_);

  QFI t1, t2, T;

  /* Using the equality gq^zm == T*com^e to compute T */
  C_dkg.Cl_G().nucompinv (T, comu, comk);
  /* Using the equality gq^zr == t1*c1^e to compute t1 */
  C.Cl_G().nucompinv (t1, cu.c1(), ck.c1());

  /* Using the equality pk^zr f^zm == t2*c2^e to compute t2 */
  C.Cl_Delta().nucompinv (t2, cu.c2(), ck.c2());

  /* Generate e using hash function and check that it matches */
  Mpz e (generate_hash (C, pk, c, com, t1, t2, T));
  Mpz::mod (e, e, C.exponent_bound_);

  ret &= (e == e_);
  return ret;
}


/* */
inline
CL_HSMqk::CL_Enc_Com_Proof::CL_Enc_Com_Proof(const Mpz zm, const Mpz zr, const Mpz e) : zm_(zm), zr_(zr), e_(e) {}

/* */
std::string CL_HSMqk::CL_Enc_Com_Proof::cl_enc_com_toString () const {
  return zm_.tostring() + " " + zr_.tostring() + " " + e_.tostring();
}


/* */
inline
Mpz CL_HSMqk::CL_Enc_Com_Proof::generate_hash (const CL_HSMqk &C,
                                        const PublicKey &pk, const CipherText &c, const QFI &com,
                                        const QFI &t1, const QFI &t2, const QFI &T) const
{
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    std::string pk_str = qfi2string(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi2string(pk.e_precomp()) + ":" + qfi2string(pk.d_precomp()) + ":" + qfi2string(pk.de_precomp());
    std::string c_str = qfi2string(c.c1()) + qfi2string(c.c2());
    std::string com_str = qfi2string(com);
    auto input = pk_str + c_str + com_str + qfi2string(t1) + qfi2string(t2) + qfi2string(T);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    BIGNUM *res = BN_new();
    BN_hex2bn(&res, ss.str().c_str());
    return Mpz (BN_bn2dec(res));
}

/* */
inline
CL_HSMqk::Encrypt_Proof CL_HSMqk::encrypt_proof (const PublicKey &pk,
                                                            const CipherText &c,
                                                            const ClearText &m,
                                                            const Mpz &r,
                                                            RandGen &randgen)
                                                            const
{
  return Encrypt_Proof (*this, pk, c, m, r, randgen);
}

/* */
inline
bool CL_HSMqk::encrypt_verify (const PublicKey &pk,
                                            const CipherText &c,
                                            const Encrypt_Proof &proof) const
{
  return proof.Encrypt_verify (*this, pk, c);
}

/* */
CL_HSMqk::Encrypt_Proof::Encrypt_Proof (const CL_HSMqk &C, const PublicKey &pk,
                              const CipherText &c, const ClearText &m,
                              const Mpz &r, RandGen &randgen)
{
  Mpz B (C.exponent_bound_);
  Mpz::mul (B, B, C.fud_factor_);
  
  Mpz sr (randgen.random_mpz (B));
  Mpz sm (randgen.random_mpz (C.M_));

  CipherText t (C.encrypt (pk, ClearText (C, sm), sr));

  /* Generate k using hash function */
  e_ = generate_hash (C, pk, c, t.c1(), t.c2());
  Mpz::mod (e_, e_, C.exponent_bound_);

  Mpz::mul (zr_, e_, r);
  Mpz::add (zr_, zr_, sr);

  Mpz::mul (zm_, e_, m);
  Mpz::add (zm_, zm_, sm);
  Mpz::mod (zm_, zm_, C.M_);
}

/* */
bool CL_HSMqk::Encrypt_Proof::Encrypt_verify (const CL_HSMqk &C,
                                    const PublicKey &pk, 
                                    const CipherText &c) const
{
  bool ret = true;

  /* Check that pk is a form in G */
  ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (pk.elt()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c1 is a form in G */
  ret &= c.c1().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (c.c1()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c2 */
  ret &= c.c2().discriminant() == C.Cl_Delta().discriminant();
  ret &= C.genus (c.c2()) == CL_HSMqk::Genus ({ 1, 1 });
  
  /* Check zr bound */
  Mpz B (C.fud_factor_);
  Mpz::add (B, B, 1UL);
  Mpz::mul (B, B, C.exponent_bound_);
  Mpz::mul (B, B, C.exponent_bound_);
  ret &= (zr_.sgn() >= 0 && zr_ <= B);
  /* Check zm bound */
  ret &= (zm_.sgn() >= 0 && zm_ < C.M_);
  /* cu = (gq^zr, pk^zr f^zm) */
  CipherText cu (C.encrypt (pk, ClearText (C, zm_), zr_));

  /* ck = (c1^e, c2^e) */
  CipherText ck (C.scal_ciphertexts (pk, c, e_, Mpz (0UL)));

  QFI t1, t2;

  /* Using the equality gq^zr == t1*c1^e to compute t1 */
  C.Cl_G().nucompinv (t1, cu.c1(), ck.c1());

  /* Using the equality pk^zr f^zm == t2*c2^e to compute t2 */
  C.Cl_Delta().nucompinv (t2, cu.c2(), ck.c2());

  /* Generate e using hash function and check that it matches */
  Mpz e (generate_hash (C, pk, c, t1, t2));
  Mpz::mod (e, e, C.exponent_bound_);

  ret &= (e == e_);
  return ret;
}

/* */
inline
CL_HSMqk::Encrypt_Proof::Encrypt_Proof(const Mpz zm, const Mpz zr, const Mpz e) : zm_(zm), zr_(zr), e_(e) {}
/* */
std::string CL_HSMqk::Encrypt_Proof::encrypt_toString () const {
  return zm_.tostring() + " " + zr_.tostring() + " " + e_.tostring();
}

/* */
inline
Mpz CL_HSMqk::Encrypt_Proof::generate_hash (const CL_HSMqk &C,
                                        const PublicKey &pk,
                                        const CipherText &c,
                                        const QFI &t1, const QFI &t2) const
{
    BN_CTX *ctx = BN_CTX_new();
    std::string pk_str = qfi2string(pk.elt()) + ":" + std::to_string(pk.d()) + ":" + std::to_string(pk.e()) + ":" + qfi2string(pk.e_precomp()) + ":" + qfi2string(pk.d_precomp()) + ":" + qfi2string(pk.de_precomp());
    std::string c_str = qfi2string(c.c1()) + qfi2string(c.c2());
    auto input = pk_str + c_str + qfi2string(t1) + qfi2string(t2);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    BIGNUM *res = BN_new();
    BN_hex2bn(&res, ss.str().c_str());
    return Mpz (BN_bn2dec(res));
}

/* */
template <>
void OpenSSL::HashAlgo::hash_update (const CL_HSMqk::PublicKey &pk)
{
  hash_update (pk.elt());
}

/* */
template <>
void OpenSSL::HashAlgo::hash_update (const CL_HSMqk::CipherText &c)
{
  hash_update (c.c1());
  hash_update (c.c2());
}

/******************************************************************************/
/* */
inline
CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                                              const Mpz &t)
  : CL_HSMqk (cryptosystem), C_exp2_ (C_exp2), H_ (OpenSSL::HashAlgo::SHAKE128)
{
  if (C_exp2_ >= M_.nbits())
    throw std::runtime_error ("the bound C=2^C_exp2 must be smaller than q^k");

  /* Set h_ to h_^t */
  Cl_G().nupow (h_, h_, t);
  /* Precomputation data must be computed again */
  h_de_precomp_ = h_;
  for (size_t i = 0; i < d_+e_; i++)
  {
    if (i == e_)
      h_e_precomp_ = h_de_precomp_;
    if (i == d_)
      h_d_precomp_ = h_de_precomp_;
    Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
  }
}


/* */
inline
CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                                              RandGen &randgen)
  : CL_HSMqk_ZKAoK (cryptosystem, C_exp2, randgen.random_mpz (cryptosystem.secretkey_bound()))
{
}

/* */
inline
CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, RandGen &randgen)
  : CL_HSMqk_ZKAoK (cryptosystem, std::min (cryptosystem.q().nbits()-1, 128UL), randgen)
{
}

/* */
inline
CL_HSMqk_ZKAoK::Proof CL_HSMqk_ZKAoK::noninteractive_proof (const PublicKey &pk,
                                                            const CipherText &c,
                                                            const ClearText &a,
                                                            const Mpz &r,
                                                            RandGen &randgen)
                                                            const
{
  return Proof (*this, pk, c, a, r, randgen);
}

/* */
inline
bool CL_HSMqk_ZKAoK::noninteractive_verify (const PublicKey &pk,
                                            const CipherText &c,
                                            const Proof &proof) const
{
  return proof.verify (*this, pk, c);
}

/* */
CL_HSMqk_ZKAoK::Proof::Proof (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                              const CipherText &c, const ClearText &a,
                              const Mpz &r, RandGen &randgen)
{
  Mpz B (C.exponent_bound_);
  Mpz::mulby2k (B, B, C.C_exp2_);
  Mpz::mul (B, B, C.fud_factor_);

  Mpz r1 (randgen.random_mpz (B));
  Mpz r2 (randgen.random_mpz (C.M_));
  CipherText t (C.encrypt (pk, ClearText (C, r2), r1));

  /* Generate k using hash function */
  k_ = k_from_hash (C, pk, c, t.c1(), t.c2());

  Mpz::mul (u1_, k_, r);
  Mpz::add (u1_, u1_, r1);

  Mpz::mul (u2_, k_, a);
  Mpz::add (u2_, u2_, r2);
  Mpz::mod (u2_, u2_, C.M_);
}

/* */
bool CL_HSMqk_ZKAoK::Proof::verify (const CL_HSMqk_ZKAoK &C,
                                    const PublicKey &pk,
                                    const CipherText &c) const
{
  bool ret = true;

  /* Check that pk is a form in G */
  ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (pk.elt()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c1 is a form in G */
  ret &= c.c1().discriminant() == C.Cl_G().discriminant();
  ret &= C.genus (c.c1()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check that c2 */
  ret &= c.c2().discriminant() == C.Cl_Delta().discriminant();
  ret &= C.genus (c.c2()) == CL_HSMqk::Genus ({ 1, 1 });

  /* Check u1 bound */
  Mpz B (C.fud_factor_);
  Mpz::add (B, B, 1UL);
  Mpz::mulby2k (B, B, C.C_exp2_);
  Mpz::mul (B, B, C.exponent_bound_);
  ret &= (u1_.sgn() >= 0 && u1_ <= B);

  /* Check u2 bound */
  ret &= (u2_.sgn() >= 0 && u2_ < C.M_);

  /* cu = (gq^u1, pk^u1 f^u2) */
  CipherText cu (C.encrypt (pk, ClearText (C, u2_), u1_));

  /* ck = (c1^k, c2^k) */
  CipherText ck (C.scal_ciphertexts (pk, c, k_, Mpz (0UL)));

  QFI t1, t2;

  /* Using the equality gq^u1 == t1*c1^k to compute t1 */
  C.Cl_G().nucompinv (t1, cu.c1(), ck.c1());

  /* Using the equality pk^u1 f^u2 == t2*c2^k to compute t2 */
  C.Cl_Delta().nucompinv (t2, cu.c2(), ck.c2());

  /* Generate k using hash function and check that it matches */
  Mpz k (k_from_hash (C, pk, c, t1, t2));
  ret &= (k == k_);

  return ret;
}

/* */
inline
Mpz CL_HSMqk_ZKAoK::Proof::k_from_hash (const CL_HSMqk_ZKAoK &C,
                                        const PublicKey &pk,
                                        const CipherText &c,
                                        const QFI &t1, const QFI &t2) const
{
  return Mpz (C.H_ (pk, c, t1, t2), C.C_exp2_);
}
#endif /* CL_HSM_INL__ */
