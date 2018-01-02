// Copyright (c) 2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "ringct/rctOps.h"
#include "ringct/bulletproofs.h"
#include "string_tools.h"
#include "common/int-util.h"

TEST(bulletproofs, valid_zero)
{
  rct::Bulletproof proof = bulletproof_PROVE(0, rct::skGen());
  ASSERT_TRUE(rct::bulletproof_VERIFY(proof));
}

TEST(bulletproofs, valid_max)
{
  rct::Bulletproof proof = bulletproof_PROVE(0xffffffffffffffff, rct::skGen());
  ASSERT_TRUE(rct::bulletproof_VERIFY(proof));
}

TEST(bulletproofs, valid_random)
{
  for (int n = 0; n < 8; ++n)
  {
    rct::Bulletproof proof = bulletproof_PROVE(crypto::rand<uint64_t>(), rct::skGen());
    ASSERT_TRUE(rct::bulletproof_VERIFY(proof));
  }
}

TEST(bulletproofs, valid_from_java)
{
    std::vector<uint64_t> amounts;
    rct::keyV gamma;

    static const struct { uint64_t amount; const char *gamma; } data[] = {
      {0xd553cbaa8fbe4a56, "ac7aaea20ddffbf5965db5b4e8fe33fed96803d0ada2a5917d16a4e8da29fa0d"},
      {0xb016438ce1f9f135, "c760a2dedb5f211bbb73c7ae52f8776fcc1696f2f7672fc23f3b5edbff5fbe01"},
      {0xeb479973bda06747, "86fe729c891af730a54033c485d5b750f5db222011736856ad4d24fed2f13d07"},
      {0x1877d8c5badaeb3f, "b19556c80765790efad28e4beabe4819da77776ae2e05cb719acacf12feb7601"},
    };
    for (const auto &x: data)
    {
      amounts.push_back(swap64(x.amount));
      rct::key g;
      ASSERT_TRUE(epee::string_tools::hex_to_pod(x.gamma, g));
      gamma.push_back(g);
    }

    rct::Bulletproof proof = bulletproof_PROVE(amounts, gamma);
    ASSERT_TRUE(rct::bulletproof_VERIFY(proof));
}

TEST(bulletproofs, valid_multi_random)
{
  for (int n = 0; n < 8; ++n)
  {
    size_t outputs = 1 << (crypto::rand<size_t>() % 4);
outputs = 2;
std::cout << "using " << outputs << " outputs" << std::endl;
    std::vector<uint64_t> amounts;
    rct::keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(crypto::rand<uint64_t>());
      gamma.push_back(rct::skGen());
    }
    rct::Bulletproof proof = bulletproof_PROVE(amounts, gamma);
    ASSERT_TRUE(rct::bulletproof_VERIFY(proof));
  }
}

TEST(bulletproofs, invalid_8)
{
  rct::key invalid_amount = rct::zero();
  invalid_amount[8] = 1;
  rct::Bulletproof proof = bulletproof_PROVE(invalid_amount, rct::skGen());
  ASSERT_FALSE(rct::bulletproof_VERIFY(proof));
}

TEST(bulletproofs, invalid_31)
{
  rct::key invalid_amount = rct::zero();
  invalid_amount[31] = 1;
  rct::Bulletproof proof = bulletproof_PROVE(invalid_amount, rct::skGen());
  ASSERT_FALSE(rct::bulletproof_VERIFY(proof));
}
