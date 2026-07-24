/*
  Copyright (c) 2026, Niobium Microsystems, Inc.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of the copyright holder nor the
        names of its contributors may be used to endorse or promote products
        derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "common.hpp"

#include <cstddef>
#include <limits>
#include <sstream>
#include <string>

// Regression test for CVE-2020-11104. On platforms where a long double occupies
// more storage than its significant bytes (e.g. x86-64), the remaining bytes are
// padding. Serializing the raw object representation would emit that padding, which
// may hold uninitialized stack/heap contents. The binary archives serialize a long
// double through a zeroed buffer so the emitted padding is always deterministic
// zeros and no memory contents leak into the archive.
//
// The check is written to be portable: instead of assuming where the padding is,
// it serializes the same value from two objects whose whole storage was first
// poisoned with different bytes. Any leaked padding would make the two byte streams
// differ. On platforms where a long double has no padding, the streams are equal
// anyway, so the test still passes.

template <class OArchive> inline
std::string serialize_poisoned_long_double(long double value, unsigned char poison)
{
  long double x;

  // Poison the whole object representation through a volatile view (writes that
  // cannot be optimized away), then assign the value. On padded platforms the
  // assignment touches only the significant bytes, leaving the poison in place.
  volatile unsigned char * storage = reinterpret_cast<volatile unsigned char *>(&x);
  for( std::size_t i = 0; i < sizeof(x); ++i )
    storage[i] = poison;
  x = value;

  std::ostringstream os;
  {
    OArchive ar(os);
    ar( x );
  }
  return os.str();
}

template <class IArchive, class OArchive> inline
void test_long_double_padding()
{
  const long double values[] =
  {
    0.0L,
    1.0L,
    -1.0L,
    3.14159265358979323846L,
    std::numeric_limits<long double>::min(),
    std::numeric_limits<long double>::max()
  };

  for( long double const value : values )
  {
    // No uninitialized padding leaks: the same value serialized from differently
    // poisoned storage must produce identical bytes.
    std::string const zeroed  = serialize_poisoned_long_double<OArchive>( value, 0x00 );
    std::string const filled  = serialize_poisoned_long_double<OArchive>( value, 0xFF );
    CHECK( zeroed == filled );

    // Zeroing the padding must not change the value: the round-trip is exact.
    long double loaded = 0.0L;
    std::istringstream is( zeroed );
    {
      IArchive ar(is);
      ar( loaded );
    }
    CHECK( loaded == value );
  }
}

TEST_SUITE_BEGIN("longdouble_padding");

TEST_CASE("binary_longdouble_padding")
{
  test_long_double_padding<cereal::BinaryInputArchive, cereal::BinaryOutputArchive>();
}

TEST_CASE("portable_binary_longdouble_padding")
{
  test_long_double_padding<cereal::PortableBinaryInputArchive, cereal::PortableBinaryOutputArchive>();
}

TEST_SUITE_END();
