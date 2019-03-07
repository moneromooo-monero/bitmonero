// Copyright (c) 2017-2018, The Monero Project
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
#include "common/apply_permutation.h"
#include "chaingen.h"
#include "multiuser.h"
#include "device/device.hpp"

using namespace epee;
using namespace crypto;
using namespace cryptonote;

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_multiuser_tx_validation_base::generate_with(std::vector<test_event_entry>& events,
    size_t inputs, size_t mixin, uint64_t amount_paid, bool valid,
    const std::function<void(std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations)> &pre_tx,
    const std::function<void(transaction &tx)> &post_tx) const
{
  uint64_t ts_start = 1338224400;
  bool r;

  constexpr size_t n_coinbases = 5;
  GENERATE_ACCOUNT(acc0);
  GENERATE_ACCOUNT(acc1);
  GENERATE_ACCOUNT(acc2);
  GENERATE_ACCOUNT(acc3);
  GENERATE_ACCOUNT(acc4);
  account_base miner_account[n_coinbases] = {acc0, acc1, acc2, acc3, acc4};

  MAKE_GENESIS_BLOCK(events, blk_0, acc0, ts_start);

  // create 8 miner accounts, and have them mine the next 8 blocks
  // they will have a coinbase with a single out that's pseudo rct
  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block blocks[n_coinbases];
  for (size_t n = 0; n < n_coinbases; ++n) {
    account_base &account = miner_account[n];
    CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[n], *prev_block, account,
        test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version | test_generator::bf_max_outs,
        4, 4, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 1, 4),
        false, "Failed to generate block");
    events.push_back(blocks[n]);
    prev_block = blocks + n;
  }

  // rewind
  cryptonote::block blk_r, blk_last;
  {
    blk_last = blocks[n_coinbases - 1];
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
    {
      cryptonote::block blk;
      CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk, blk_last, miner_account[0],
          test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version | test_generator::bf_max_outs,
          4, 4, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 1, 4),
          false, "Failed to generate block");
      events.push_back(blk);
      blk_last = blk;
    }
    blk_r = blk_last;
  }

  cryptonote::keypair in_ephemeral;
  crypto::public_key tx_pub_key[n_coinbases];
  crypto::public_key output_pub_key[n_coinbases];
  for (size_t n = 0; n < n_coinbases; ++n)
  {
    tx_pub_key[n] = get_tx_pub_key_from_extra(blocks[n].miner_tx);
    MDEBUG("tx_pub_key: " << tx_pub_key[n]);
    output_pub_key[n] = boost::get<txout_to_key>(blocks[n].miner_tx.vout[0].target).key;
    MDEBUG("output_pub_key: " << output_pub_key[n]);
  }

  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses[n_coinbases];
  for (size_t i = 0; i < n_coinbases; ++i)
    subaddresses[i][miner_account[i].get_keys().m_account_address.m_spend_public_key] = {0,0};

  // create a tx: we have 8 outputs, all from coinbase, so "fake" rct - use 2
  std::vector<tx_source_entry> sources;
  for (size_t n = 0; n < inputs; ++n)
  {
    sources.resize(sources.size() + 1);
    tx_source_entry& src = sources.back();

    src.real_output = n;
    src.amount = blocks[n].miner_tx.vout[0].amount;
    src.real_out_tx_key = tx_pub_key[n];
    src.real_output_in_tx_index = 0;
    src.mask = rct::identity();
    src.rct = true;
    src.owned = false;
    cryptonote::keypair in_ephemeral;
    r = cryptonote::generate_key_image_helper(miner_account[n].get_keys(), subaddresses[n],
        boost::get<txout_to_key>(blocks[n].miner_tx.vout[0].target).key, tx_pub_key[n], {}, src.real_output_in_tx_index,
        in_ephemeral, src.mu_ki, hw::get_device("default"));
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key image");

    for (size_t m = 0; m <= mixin; ++m)
    {
      rct::ctkey ctkey;
      ctkey.dest = rct::pk2rct(boost::get<txout_to_key>(blocks[m].miner_tx.vout[0].target).key);
      MDEBUG("using " << (m == n ? "real" : "fake") << " input " << ctkey.dest);
      ctkey.mask = rct::commit(blocks[m].miner_tx.vout[0].amount, rct::identity()); // since those are coinbases, the masks are known
      src.outputs.push_back(std::make_pair(m, ctkey));
    }
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
  rct::multiuser_out muout;
  std::vector<crypto::secret_key> additional_tx_secret_keys;
  auto sources_copy = sources;
  r = construct_tx_and_get_tx_key(miner_account[0].get_keys(), subaddresses[0], sources, destinations, boost::none, std::vector<uint8_t>(), tx, 0, tx_key, additional_tx_secret_keys, true, {rct::RangeProofBulletproof, 1}, NULL, &muout);
  CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

  // work out the permutation done on sources
  std::vector<size_t> ins_order;
  for (size_t n = 0; n < sources.size(); ++n)
  {
    for (size_t idx = 0; idx < sources_copy.size(); ++idx)
    {
      CHECK_AND_ASSERT_MES((size_t)sources_copy[idx].real_output < sources_copy[idx].outputs.size(),
          false, "Invalid real_output");
      if (sources_copy[idx].outputs[sources_copy[idx].real_output].second.dest == sources[n].outputs[sources[n].real_output].second.dest)
        ins_order.push_back(idx);
    }
  }
  CHECK_AND_ASSERT_MES(ins_order.size() == sources.size(), false, "Failed to work out sources permutation");

  // verify this tx is really to the expected address
  const crypto::public_key tx_pub_key2 = get_tx_pub_key_from_extra(tx, 0);
  crypto::key_derivation derivation;
  r = crypto::generate_key_derivation(tx_pub_key2, miner_account[0].get_keys().m_view_secret_key, derivation);
  CHECK_AND_ASSERT_MES(r, false, "Failed to generate derivation");
  std::vector<crypto::key_derivation> additional_derivations;
  const std::vector<crypto::public_key> additional_tx_pub_keys2 = get_additional_tx_pub_keys_from_extra(tx);
  for (const crypto::public_key &pkey: additional_tx_pub_keys2)
  {
    additional_derivations.resize(additional_derivations.size() + 1);
    r = crypto::generate_key_derivation(pkey, miner_account[0].get_keys().m_view_secret_key, additional_derivations.back());
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate derivation");
  }
  uint64_t n_outs = 0, amount = 0;
  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    CHECK_AND_ASSERT_MES(typeid(txout_to_key) == tx.vout[n].target.type(), false, "Unexpected tx out type");
    if (is_out_to_acc_precomp(subaddresses[0], boost::get<txout_to_key>(tx.vout[n].target).key, derivation, additional_derivations, n, hw::get_device(("default"))))
    {
      ++n_outs;
      CHECK_AND_ASSERT_MES(tx.vout[n].amount == 0, false, "Destination amount is not zero");
      rct::key Ctmp;
      crypto::secret_key scalar1;
      crypto::derivation_to_scalar(derivation, n, scalar1);
      rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
      rct::ecdhDecode(ecdh_info, rct::sk2rct(scalar1), false);
      rct::key C = tx.rct_signatures.outPk[n].mask;
      rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
      CHECK_AND_ASSERT_MES(rct::equalKeys(C, Ctmp), false, "Failed to decode amount");
      amount += rct::h2d(ecdh_info.amount);
    }
  }
  CHECK_AND_ASSERT_MES(n_outs == 1, false, "Not exactly 1 output was received");
  CHECK_AND_ASSERT_MES(amount == amount_paid, false, "Amount paid was not the expected amount");

  // sign it
  std::vector<unsigned int> index(inputs);
  for (size_t i = 0; i < inputs; ++i)
    index[i] = i;
  tools::apply_permutation(ins_order, index);
  for (size_t i = 0; i < inputs; ++i)
  {
    std::vector<bool> owned(inputs, false);
    owned[ins_order[i]] = true;
    rct::ctkeyV inSk(inputs);
    cryptonote::keypair in_ephemeral;
    crypto::key_image ki;
    r = cryptonote::generate_key_image_helper(miner_account[i].get_keys(), subaddresses[i],
        boost::get<txout_to_key>(blocks[i].miner_tx.vout[0].target).key, tx_pub_key[i], {}, 0,
        in_ephemeral, ki, hw::get_device("default"));
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key image");
    for (auto &ctk: inSk)
    {
      ctk.dest = rct::zero();
      ctk.mask = rct::identity();
    }
    inSk[ins_order[i]].dest = rct::sk2rct(in_ephemeral.sec);
    inSk[ins_order[i]].mask = rct::identity(); // the inputs are coinbases
    r = rct::signMultiuser(tx.rct_signatures, inSk, owned, muout, hw::get_device("default"));
    CHECK_AND_ASSERT_MES(r, false, "Failed to sign multiuser transaction");
  }

  if (post_tx)
    post_tx(tx);

  if (!valid)
    DO_CALLBACK(events, "mark_invalid_tx");
  events.push_back(tx);

  return true;
}

bool gen_multiuser_tx_valid_1_1::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 4;
  const uint64_t amount_paid = 10000;
  return generate_with(events, 2, mixin, amount_paid, true, NULL, NULL);
}
