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

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

static const unsigned char TESTDATA1[1] = {42};
static const unsigned char TESTDATA32[32] = {0xff, 0xff, 0, 0x23, 0xe3, 0x9f, 0x03, 0x58, 0x4d, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xd2, 0xfe};
static const unsigned char TESTKEY32[32] = {0, 0, 0, 0x23, 0xe3, 0x9f, 0x03, 0x58, 0x4d, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0};
static const crypto::secret_key &TESTKEY = (const crypto::secret_key&)TESTKEY32;

TEST(encrypt_secret_key, works)
{
  crypto::secret_key key = cryptonote::encrypt_key(TESTKEY, "");
  key = cryptonote::decrypt_key(key, "");
  ASSERT_EQ(key, TESTKEY);
}

TEST(encrypt_data_deterministic, empty)
{
  std::string plaintext;
  std::string ciphertext = cryptonote::encrypt_data_deterministic(plaintext, "");
  std::string decrypted = cryptonote::decrypt_data_deterministic(ciphertext, "");
  ASSERT_EQ(decrypted, plaintext);
}

TEST(encrypt_data_deterministic, one)
{
  std::string plaintext(1, '\x42');
  std::string ciphertext = cryptonote::encrypt_data_deterministic(plaintext, "");
  std::string decrypted = cryptonote::decrypt_data_deterministic(ciphertext, "");
  ASSERT_EQ(decrypted, plaintext);
}

TEST(encrypt_data_deterministic, long)
{
  std::string plaintext(256, ' ');
  for (int n = 0; n < 255; ++n) plaintext[n] = n;
  std::string ciphertext = cryptonote::encrypt_data_deterministic(plaintext, "");
  std::string decrypted = cryptonote::decrypt_data_deterministic(ciphertext, "");
  ASSERT_EQ(decrypted, plaintext);
}

TEST(encrypt_data_deterministic, deterministic)
{
  std::string plaintext(256, ' ');
  for (int n = 0; n < 255; ++n) plaintext[n] = n;
  std::string ciphertext0 = cryptonote::encrypt_data_deterministic(plaintext, "");
  std::string decrypted0 = cryptonote::decrypt_data_deterministic(ciphertext0, "");
  std::string ciphertext1 = cryptonote::encrypt_data_deterministic(plaintext, "");
  std::string decrypted1 = cryptonote::decrypt_data_deterministic(ciphertext1, "");
  ASSERT_EQ(decrypted0, decrypted1);
}

