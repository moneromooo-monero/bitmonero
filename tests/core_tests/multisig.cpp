// Copyright (c) 2014-2017, The Monero Project
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

#include "ringct/rctSigs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/multisig.h"
#include "chaingen.h"
#include "chaingen_tests_list.h"

using namespace epee;
using namespace crypto;
using namespace cryptonote;

//#define NO_MULTISIG

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_multisig_tx_validation_base::generate_with(std::vector<test_event_entry>& events,
    int mixin, uint64_t amount_paid, bool valid,
    const std::function<void(std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations)> &pre_tx,
    const std::function<void(transaction &tx)> &post_tx) const
{
  uint64_t ts_start = 1338224400;
  bool r;

#ifdef NO_MULTISIG
  GENERATE_ACCOUNT(acc0);
  GENERATE_ACCOUNT(acc1);
  GENERATE_ACCOUNT(acc2);
  account_base miner_account[3] = {acc0, acc1, acc2 };
#else
  GENERATE_MULTISIG_ACCOUNT(miner_account, 2, 3);
#endif

  MAKE_GENESIS_BLOCK(events, blk_0, miner_account[0], ts_start);

  // create 8 miner accounts, and have them mine the next 8 blocks
  // they will have a coinbase with a single out that's pseudo rct
  const size_t n_coinbases = 8;
  cryptonote::account_base miner_accounts[n_coinbases];
  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block blocks[n_coinbases];
  for (size_t n = 0; n < n_coinbases; ++n) {
    // the first block goes to the multisig account
    miner_accounts[n].generate();
    account_base &account = n == 0 ? miner_account[0] : miner_accounts[n];
    CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[n], *prev_block, account,
        test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version | test_generator::bf_max_outs,
        4, 4, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 1, 4),
        false, "Failed to generate block");
    events.push_back(blocks[n]);
    prev_block = blocks + n;
    LOG_PRINT_L0("Initial miner tx " << n << ": " << obj_to_json_str(blocks[n].miner_tx));
    LOG_PRINT_L0("in block: " << obj_to_json_str(blocks[n]));
  }

  // rewind
  cryptonote::block blk_r, blk_last;
  {
    blk_last = blocks[n_coinbases - 1];
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
    {
      cryptonote::block blk;
      CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk, blk_last, miner_accounts[0],
          test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version | test_generator::bf_max_outs,
          4, 4, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 1, 4),
          false, "Failed to generate block");
      events.push_back(blk);
      blk_last = blk;
    }
    blk_r = blk_last;
  }

  const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(blocks[0].miner_tx);
  MDEBUG("tx_pub_key: " << tx_pub_key);
  const crypto::public_key output_pub_key = boost::get<txout_to_key>(blocks[0].miner_tx.vout[0].target).key;
  MDEBUG("output_pub_key: " << output_pub_key);
  cryptonote::keypair in_ephemeral;

#ifndef NO_MULTISIG
  // create k/L/R/ki for that output we're going to spend
  crypto::secret_key account_k[3];
  crypto::public_key account_L[3];
  crypto::public_key account_R[3];
  crypto::key_image account_ki[3][2];
  for (size_t msidx = 0; msidx < 3; ++msidx)
  {
    account_k[msidx] = rct::rct2sk(rct::skGen());
    cryptonote::generate_multisig_LR(output_pub_key, account_k[msidx], account_L[msidx], account_R[msidx]);
    r = cryptonote::generate_multisig_key_image(miner_account[msidx].get_keys(), tx_pub_key, 0, in_ephemeral, account_ki[msidx][0], 0);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate multisig export key image");
    r = cryptonote::generate_multisig_key_image(miner_account[msidx].get_keys(), tx_pub_key, 0, in_ephemeral, account_ki[msidx][1], 1);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate multisig export key image");
    MDEBUG("Party " << msidx << ":");
    MDEBUG("spend: sec " << miner_account[msidx].get_keys().m_spend_secret_key << ", pub " << miner_account[msidx].get_keys().m_account_address.m_spend_public_key);
    MDEBUG("view: sec " << miner_account[msidx].get_keys().m_view_secret_key << ", pub " << miner_account[msidx].get_keys().m_account_address.m_view_public_key);
    MDEBUG("msk0: " << miner_account[msidx].get_multisig_keys()[0]);
    MDEBUG("msk1: " << miner_account[msidx].get_multisig_keys()[1]);
    MDEBUG("k: " << account_k[msidx]);
    MDEBUG("L: " << account_L[msidx]);
    MDEBUG("R: " << account_R[msidx]);
    MDEBUG("ki: " << account_ki[msidx][0] << ", " << account_ki[msidx][1]);
  }
#endif

  // create kLRki
  rct::multisig_kLRki kLRki;
#ifdef NO_MULTISIG
  kLRki = {rct::zero(), rct::zero(), rct::zero(), rct::zero()};
#else
  kLRki.k = rct::sk2rct(account_k[0]);
  kLRki.L = rct::pk2rct(account_L[0]);
  kLRki.R = rct::pk2rct(account_R[0]);
  MDEBUG("Starting with k " << kLRki.k);
  MDEBUG("Starting with L " << kLRki.L);
  MDEBUG("Starting with R " << kLRki.R);
  std::unordered_set<crypto::public_key> used_L;
  for (size_t msidx = 0; msidx < 3; ++msidx)
  {
    if (msidx == 0 /* creator */)
      continue;
    if (msidx == 2 /* non-signer */)
      continue;
    if (used_L.find(account_L[msidx]) == used_L.end())
    {
      used_L.insert(account_L[msidx]);
      MDEBUG("Adding L " << account_L[msidx] << " (for k " << account_k[msidx] << ")");
      MDEBUG("Adding R " << account_R[msidx]);
      rct::addKeys((rct::key&)kLRki.L, kLRki.L, rct::pk2rct(account_L[msidx]));
      rct::addKeys((rct::key&)kLRki.R, kLRki.R, rct::pk2rct(account_R[msidx]));
    }
  }
  std::vector<crypto::key_image> pkis;
  for (size_t msidx = 0; msidx < 3; ++msidx)
    for (size_t n = 0; n < 2; ++n)
      pkis.push_back(account_ki[msidx][n]);
  r = cryptonote::generate_multisig_composite_key_image(miner_account[0].get_keys(), tx_pub_key, 0, pkis, (crypto::key_image&)kLRki.ki);
  CHECK_AND_ASSERT_MES(r, false, "Failed to generate composite key image");
  MDEBUG("composite ki: " << kLRki.ki);
  MDEBUG("L: " << kLRki.L);
  MDEBUG("R: " << kLRki.R);
  rct::key ki1;
  r = cryptonote::generate_multisig_composite_key_image(miner_account[1].get_keys(), tx_pub_key, 0, pkis, (crypto::key_image&)ki1);
  CHECK_AND_ASSERT_MES(r, false, "Failed to generate composite key image");
  CHECK_AND_ASSERT_MES(kLRki.ki == ki1, false, "Composite key images do not match");
  rct::key ki2;
  r = cryptonote::generate_multisig_composite_key_image(miner_account[2].get_keys(), tx_pub_key, 0, pkis, (crypto::key_image&)ki2);
  CHECK_AND_ASSERT_MES(r, false, "Failed to generate composite key image");
  CHECK_AND_ASSERT_MES(kLRki.ki == ki2, false, "Composite key images do not match");
#endif

  // create a tx: we have 8 outputs, all from coinbase, so "fake" rct
  std::vector<tx_source_entry> sources;
  sources.resize(1);
  tx_source_entry& src = sources.back();

  src.real_output = 0;
  src.amount = blocks[0].miner_tx.vout[0].amount;
  src.real_out_tx_key = tx_pub_key;
  src.real_output_in_tx_index = 0;
  src.mask = rct::identity();
  src.rct = true;
  src.multisig_kLRki = kLRki;

  for (int m = 0; m <= mixin; ++m)
  {
    rct::ctkey ctkey;
    ctkey.dest = rct::pk2rct(boost::get<txout_to_key>(blocks[m].miner_tx.vout[0].target).key);
    MDEBUG("using " << (m == 0 ? "real" : "fake") << " input " << ctkey.dest);
    ctkey.mask = rct::commit(blocks[m].miner_tx.vout[0].amount, rct::identity()); // since those are coinbases, the masks are known
    src.outputs.push_back(std::make_pair(m, ctkey));
  }

  //fill outputs entry
  tx_destination_entry td;
  td.addr = miner_account[0].get_keys().m_account_address;
  td.amount = amount_paid;
  std::vector<tx_destination_entry> destinations;
  destinations.push_back(td);

  if (pre_tx)
    pre_tx(sources, destinations);

  transaction tx;
  crypto::secret_key tx_key;
#ifdef NO_MULTISIG
  rct::multisig_out *msoutp = NULL;
#else
  rct::multisig_out msout;
  msout.seed = 0;
  rct::multisig_out *msoutp = &msout;
#endif
  r = construct_tx_and_get_tx_key(miner_account[0].get_keys(), sources, destinations, std::vector<uint8_t>(), tx, 0, tx_key, true, msoutp);
  CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

#ifndef NO_MULTISIG
  // sign
  int secret_key_index = -1;
  const std::vector<crypto::secret_key> &msk0 = miner_account[0].get_multisig_keys(), &msk1 = miner_account[1].get_multisig_keys();
  for (size_t n = 0; n < msk1.size(); ++n)
  {
    const crypto::secret_key &sk1 = msk1[n];
    auto i = std::find_if(msk0.begin(), msk0.end(), [&sk1](const crypto::secret_key &sk0) { return !memcmp(&sk0, &sk1, sizeof(sk0)); });
    if (i == msk0.end())
    {
      secret_key_index = n;
      break;
    }
  }
  CHECK_AND_ASSERT_MES(secret_key_index >= 0, false, "failed to find secret multisig key to sign transaction");
  std::vector<unsigned int> indices;
  for (const auto &src: sources)
    indices.push_back(src.real_output);
  rct::keyV k;
  k.push_back(rct::zero());
  sc_add(k.back().bytes, k.back().bytes, rct::sk2rct(account_k[1]).bytes);
  crypto::secret_key skey = msk1[secret_key_index];
  MDEBUG("signing with k size " << k.size());
  MDEBUG("signing with k " << k.back());
  MDEBUG("signing with sk " << skey);
  MDEBUG("  created with sk " << msk0[0] << " and " << msk0[1]);
  const std::vector<crypto::secret_key> &msk2 = miner_account[2].get_multisig_keys();
  MDEBUG("  NOT created with sk " << msk2[0] << " and " << msk2[1]);
  MDEBUG("signing with c size " << msout.c.size());
  MDEBUG("signing with c " << msout.c.back());
  r = rct::signMultisig(tx.rct_signatures, indices, k, msout, rct::sk2rct(skey));
  CHECK_AND_ASSERT_MES(r, false, "failed to sign transaction");
  MDEBUG("signed tx: " << cryptonote::obj_to_json_str(tx));
#endif

  if (post_tx)
    post_tx(tx);

  if (!valid)
    DO_CALLBACK(events, "mark_invalid_tx");
  events.push_back(tx);
  LOG_PRINT_L0("Test tx: " << obj_to_json_str(tx));

  return true;
}

bool gen_multisig_tx_valid::generate(std::vector<test_event_entry>& events) const
{
  const int mixin = 4;
  const uint64_t amount_paid = 10000;
  return generate_with(events, mixin, amount_paid, true, NULL, NULL);
}
