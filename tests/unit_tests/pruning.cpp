// Copyright (c) 2018, The Monero Project
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

#include "misc_log_ex.h"
#include "cryptonote_config.h"
#include "common/pruning.h"

TEST(pruning, tip)
{
  static constexpr uint64_t H = 1000;
  static_assert(H >= CRYPTONOTE_PRUNING_TIP_BLOCKS, "H must be >= CRYPTONOTE_PRUNING_TIP_BLOCKS");
  for (uint64_t h = H - CRYPTONOTE_PRUNING_TIP_BLOCKS; h < H; ++h)
  {
    uint32_t pruning_seed = tools::get_pruning_seed(h, H);
    ASSERT_EQ(pruning_seed, 0);
    for (pruning_seed = 0; pruning_seed <= 1 << CRYPTONOTE_PRUNING_LOG_STRIPES; ++pruning_seed)
      ASSERT_TRUE(tools::has_unpruned_block(h, H, pruning_seed));
  }
}

TEST(pruning, match)
{
  static constexpr uint64_t H = 1000;
  static_assert(H >= CRYPTONOTE_PRUNING_TIP_BLOCKS, "H must be >= CRYPTONOTE_PRUNING_TIP_BLOCKS");
  for (uint64_t h = 0; h < H - CRYPTONOTE_PRUNING_TIP_BLOCKS; ++h)
  {
    uint32_t pruning_seed = tools::get_pruning_seed(h, H);
    ASSERT_TRUE(pruning_seed > 0 && pruning_seed <= (1 << CRYPTONOTE_PRUNING_LOG_STRIPES));
    for (uint32_t other_pruning_seed = 1; other_pruning_seed <= (1 << CRYPTONOTE_PRUNING_LOG_STRIPES); ++other_pruning_seed)
    {
      ASSERT_TRUE(tools::has_unpruned_block(h, H, other_pruning_seed) == (other_pruning_seed == pruning_seed));
    }
  }
}

TEST(pruning, stripe_size)
{
  static constexpr uint64_t H = 1000;
  static_assert(H >= CRYPTONOTE_PRUNING_TIP_BLOCKS + CRYPTONOTE_PRUNING_STRIPE_SIZE * (1 << CRYPTONOTE_PRUNING_LOG_STRIPES), "H must be >= that stuff in front");
  for (uint32_t pruning_seed = 1; pruning_seed <= (1 << CRYPTONOTE_PRUNING_LOG_STRIPES); ++pruning_seed)
  {
    unsigned int current_run = 0, best_run = 0;
    for (uint64_t h = 0; h < H - CRYPTONOTE_PRUNING_TIP_BLOCKS; ++h)
    {
      if (tools::has_unpruned_block(h, H, pruning_seed))
      {
        ++current_run;
      }
      else if (current_run)
      {
        ASSERT_EQ(current_run, CRYPTONOTE_PRUNING_STRIPE_SIZE);
        best_run = std::max(best_run, current_run);
        current_run = 0;
      }
    }
    ASSERT_EQ(best_run, CRYPTONOTE_PRUNING_STRIPE_SIZE);
  }
}

TEST(pruning, next)
{
  for (uint64_t h = 0; h < 100; ++h)
    ASSERT_EQ(tools::get_next_unpruned_block_height(h, 1000, 0), h);

  ASSERT_EQ(tools::get_next_unpruned_block_height(0, 1000, 1), 0);
  ASSERT_EQ(tools::get_next_unpruned_block_height(1, 1000, 1), 1);
  ASSERT_EQ(tools::get_next_unpruned_block_height(7, 1000, 1), 7);
  ASSERT_EQ(tools::get_next_unpruned_block_height(8, 1000, 1), 32);

  ASSERT_EQ(tools::get_next_unpruned_block_height(0, 1000, 2), 8);
  ASSERT_EQ(tools::get_next_unpruned_block_height(1, 1000, 2), 8);
  ASSERT_EQ(tools::get_next_unpruned_block_height(7, 1000, 2), 8);
  ASSERT_EQ(tools::get_next_unpruned_block_height(8, 1000, 2), 40);

  ASSERT_EQ(tools::get_next_unpruned_block_height(8, 1000, 3), 48);

  ASSERT_EQ(tools::get_next_unpruned_block_height(8, 1000, 4), 56);
}
