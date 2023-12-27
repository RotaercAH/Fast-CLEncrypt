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
#include <string>
#include <sstream>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;

using namespace BICYCL;

/* */
bool
test_commitments (const thresholdECDSA &C, size_t niter, const string &pre)
{
  bool ret = true;

  thresholdECDSA::Commitment c;
  thresholdECDSA::Bytes r;

  for (size_t i = 0; i < niter; i++)
  {
    OpenSSL::ECKey k (C.get_ec_group());
    OpenSSL::ECPoint::RawSrcPtr Q = k.get_ec_point();
    tie(c, r) = C.commit (Q);
    ret &= C.open (c, Q, r);
  }

  Test::result_line (pre, ret);
  return ret;
}

/******************************************************************************/
bool check (SecLevel seclevel, RandGen &randgen, size_t niter)
{
  bool success = true;

  std::stringstream desc;
  desc << "security " << seclevel << " bits";

  thresholdECDSA C (seclevel, randgen);
  desc << " ECDSA";

  success &= test_commitments (C, niter, desc.str());

  return success;
}

/******************************************************************************/
int
main (int argc, char *argv[])
{
  bool success = true;

  RandGen randgen;
  randseed_from_argv (randgen, argc, argv);

  Test::OverrideOpenSSLRand::WithRandGen tmp_override (randgen);

  success &= check (SecLevel::_112, randgen, 50);
  success &= check (SecLevel::_128, randgen, 50);
  success &= check (SecLevel::_192, randgen, 50);
  success &= check (SecLevel::_256, randgen, 50);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
