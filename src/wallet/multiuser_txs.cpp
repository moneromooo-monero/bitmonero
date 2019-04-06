// Copyright (c) 2014-2019, The Monero Project
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

#include <numeric>
#include <random>
#include <tuple>
#include "include_base_utils.h"
#include "cryptonote_config.h"
#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "memwipe.h"
#include "common/perf_timer.h"
#include "ringct/rctSigs.h"

#warning remove
#include "ringct/bulletproofs.h"

//using namespace std;
//using namespace crypto;
//using namespace cryptonote;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2.multiuser"

#define MULTIUSER_SETUP_PREFIX "Monero multiuser setup\001"
#define MULTIUSER_TX_PREFIX "Monero multiuser tx set\001"

namespace
{
  bool is_suitable_for_multiuser(const cryptonote::transaction &tx)
  {
    if (tx.version < 2)
    {
      MERROR("Tx version is not >= 2");
      return false;
    }
    const rct::rctSig &rv = tx.rct_signatures;
    if (!rct::is_rct_simple(rv.type))
    {
      MERROR("multiuser tx is not simple");
      return false;
    }
    if (!rct::is_rct_bulletproof(rv.type))
    {
      MERROR("multiuser tx is not bulletproof");
      return false;
    }
    return true;
  }

  struct multiuser_setup
  {
    std::string private_setup;
    std::string public_setup;

    BEGIN_SERIALIZE_OBJECT();
      FIELD(private_setup)
      FIELD(public_setup)
    END_SERIALIZE();
  };

  template <class Archive>
  inline void serialize(Archive &a, multiuser_setup &x, const boost::serialization::version_type ver)
  {
    a & x.private_setup;
    a & x.public_setup;
  }
}

namespace tools
{
//----------------------------------------------------------------------------------------------------
bool wallet2::save_multiuser_setup(const multiuser_private_setup &private_setup, const multiuser_public_setup &public_setup, std::string &data) const
{
  std::ostringstream oss0;
  boost::archive::portable_binary_oarchive ar0(oss0);
  try { ar0 << private_setup; }
  catch (...) { return false; }

  std::ostringstream oss1;
  boost::archive::portable_binary_oarchive ar1(oss1);
  try { ar1 << public_setup; }
  catch (...) { return false; }

  multiuser_setup multiuser_setup;
  multiuser_setup.private_setup = encrypt_with_view_secret_key(oss0.str());
  multiuser_setup.public_setup = oss1.str();

  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try { ar << multiuser_setup; }
  catch (...) { return false; }

  data = MULTIUSER_SETUP_PREFIX + authenticate(oss.str(), get_account().get_keys().m_view_secret_key);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_multiuser_setup(std::string data, multiuser_private_setup &private_setup, multiuser_public_setup &public_setup, bool &ours) const
{
  if (!boost::string_ref{data}.starts_with(MULTIUSER_SETUP_PREFIX))
  {
    MERROR("Decrypted multiuser setup has invalid magic");
    return false;
  }

  const size_t prefix_size = strlen(MULTIUSER_SETUP_PREFIX);
  data = std::string(data.data() + prefix_size, data.size() - prefix_size);

  if (data.size() < sizeof(crypto::signature))
    return false;

  ours = verify_authenticity(data, get_account().get_keys().m_view_secret_key);

  data = std::string(data.data(), data.size() - sizeof(crypto::signature));

  multiuser_setup multiuser_setup;
  try
  {
    std::istringstream iss(data);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> multiuser_setup;
  }
  catch (...)
  {
    MERROR("Failed to parse data from multiuser setup");
    return false;
  }

  if (ours)
  {
    try
    {
      std::string data = decrypt_with_view_secret_key(multiuser_setup.private_setup);
      std::istringstream iss(data);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> private_setup;
    }
    catch (...)
    {
      MERROR("Failed to parse data from multiuser private setup");
      return false;
    }
  }

  try
  {
    std::istringstream iss(multiuser_setup.public_setup);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> public_setup;
  }
  catch (...)
  {
    MERROR("Failed to parse data from multiuser public setup");
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::save_multiuser_tx(const multiuser_tx_set &txs)
{
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << txs;
  }
  catch (...)
  {
    return "";
  }
  return MULTIUSER_TX_PREFIX + oss.str();
}
//----------------------------------------------------------------------------------------------------
bool wallet2::save_multiuser_tx_to_file(const multiuser_tx_set &txs, const std::string &filename)
{
  std::string data = save_multiuser_tx(txs);
  if (data.empty())
    return false;
  return epee::file_io_utils::save_string_to_file(filename, data);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_multiuser_tx(const std::string &data, multiuser_tx_set &txs, std::function<bool(const multiuser_tx_set&)> accept_func)
{
  if (!boost::string_ref{data}.starts_with(MULTIUSER_TX_PREFIX))
  {
    MERROR("Invalid multiuser tx set prefix");
    return false;
  }

  try
  {
    std::istringstream iss(data.substr(strlen(MULTIUSER_TX_PREFIX)));
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> txs;
  }
  catch (...)
  {
    MERROR("Failed to parse data from multiuser setup");
    return false;
  }
  if (accept_func && !accept_func(txs))
  {
    MERROR("Accept callback returned false");
    return false;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_multiuser_tx_from_file(const std::string &filename, multiuser_tx_set &txs, std::function<bool(const multiuser_tx_set&)> accept_func)
{
  std::string s;
  boost::system::error_code errcode;

  if (!boost::filesystem::exists(filename, errcode))
  {
    MERROR("File " << filename << " does not exist: " << errcode);
    return false;
  }
  if (!epee::file_io_utils::load_file_to_string(filename.c_str(), s))
  {
    MERROR("Failed to load from " << filename);
    return false;
  }

  return load_multiuser_tx(s, txs, accept_func);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::pre_merge_multiuser(multiuser_tx_set &multiuser_txs, const pending_tx &ptx, const std::vector<cryptonote::tx_destination_entry> &dsts, const std::vector<cryptonote::tx_destination_entry> &other_dsts, const rct::multiuser_out &muout, bool disclose)
{
  tools::wallet2::multiuser_private_setup private_setup;
  tools::wallet2::multiuser_public_setup public_setup;

  private_setup.vin = ptx.tx.vin;
  private_setup.muout = muout;
  private_setup.tx_key = cryptonote::get_tx_pub_key_from_extra(ptx.tx);
  private_setup.additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(ptx.tx);

  if (disclose)
  {
    for (const cryptonote::tx_destination_entry &dst: dsts)
      public_setup.dests.push_back(dst);
  }
  public_setup.conditions = other_dsts;
  public_setup.unlock_time = ptx.tx.unlock_time;

  if (!merge_multiuser_tx(multiuser_txs, ptx, disclose, private_setup.vout))
  {
    MERROR("Failed to merge multiuser transactions");
    return false;
  }

  std::string data;
  if (!save_multiuser_setup(private_setup, public_setup, data))
  {
    MERROR("Failed to save multiuser setup");
    return false;
  }

  multiuser_txs.m_setup.push_back(data);

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::merge_multiuser_tx(multiuser_tx_set &multiuser_txs, const pending_tx &ptx, bool disclose, std::vector<std::vector<std::tuple<cryptonote::tx_out, crypto::secret_key, rct::ecdhTuple, rct::key, rct::Bulletproof>>> &vouts)
{
  const bool first = multiuser_txs.m_ptx.tx == cryptonote::transaction();
  CHECK_AND_ASSERT_THROW_MES(first || is_suitable_for_multiuser(multiuser_txs.m_ptx.tx), "Transaction is not suitable for multiuser");
  CHECK_AND_ASSERT_THROW_MES(is_suitable_for_multiuser(ptx.tx), "Transaction is not suitable for multiuser");

  CHECK_AND_ASSERT_THROW_MES(multiuser_txs.m_building, "Multiuser transaction cannot be modified once signing has started");

  // use the new tx as a base
  pending_tx new_ptx = ptx;
  rct::ctkeyM new_mixRing;
  const pending_tx &old_ptx = multiuser_txs.m_ptx;
  const size_t output_offset = multiuser_txs.m_ptx.tx.vout.size();

  // copy existing vins/vouts
  CHECK_AND_ASSERT_THROW_MES(old_ptx.tx.vin.size() == multiuser_txs.m_mixRing.size(), "Invalid vin/mixRing size");
  new_ptx.tx.vin = old_ptx.tx.vin;
  new_ptx.tx.vout = old_ptx.tx.vout;
  new_ptx.tx.rct_signatures.p.pseudoOuts = old_ptx.tx.rct_signatures.p.pseudoOuts;
  new_ptx.tx.rct_signatures.outPk = old_ptx.tx.rct_signatures.outPk;
  new_ptx.tx.rct_signatures.ecdhInfo = old_ptx.tx.rct_signatures.ecdhInfo;
  new_ptx.tx.rct_signatures.p.bulletproofs = old_ptx.tx.rct_signatures.p.bulletproofs;
  new_mixRing = multiuser_txs.m_mixRing;

  new_ptx.tx.vout = old_ptx.tx.vout;

  CHECK_AND_ASSERT_THROW_MES(ptx.tx.vin.size() == ptx.tx.rct_signatures.mixRing.size(), "Invalid vin/mixRing size");
  CHECK_AND_ASSERT_THROW_MES(ptx.tx.vin.size() == ptx.tx.rct_signatures.p.pseudoOuts.size(), "Invalid vin/pseudoOuts size");
  for (size_t i = 0; i < ptx.tx.vin.size(); ++i)
  {
    new_ptx.tx.vin.push_back(ptx.tx.vin[i]);
    new_ptx.tx.rct_signatures.p.pseudoOuts.push_back(ptx.tx.rct_signatures.p.pseudoOuts[i]);
    new_mixRing.push_back(ptx.tx.rct_signatures.mixRing[i]);
  }

  CHECK_AND_ASSERT_THROW_MES(ptx.tx.vout.size() == ptx.tx.rct_signatures.outPk.size(), "Invalid vout/outPk size");
  CHECK_AND_ASSERT_THROW_MES(ptx.tx.vout.size() == ptx.tx.rct_signatures.ecdhInfo.size(), "Invalid vout/ecdhInfo size");
  for (size_t i = 0; i < ptx.tx.vout.size(); ++i)
  {
    new_ptx.tx.vout.push_back(ptx.tx.vout[i]);
    new_ptx.tx.rct_signatures.outPk.push_back(ptx.tx.rct_signatures.outPk[i]);
    new_ptx.tx.rct_signatures.ecdhInfo.push_back(ptx.tx.rct_signatures.ecdhInfo[i]);
  }

  for (const rct::Bulletproof &proof: ptx.tx.rct_signatures.p.bulletproofs)
    new_ptx.tx.rct_signatures.p.bulletproofs.push_back(proof);

  new_ptx.tx.rct_signatures.txnFee = (first ? 0 : old_ptx.tx.rct_signatures.txnFee) + ptx.tx.rct_signatures.txnFee;

  // sort inputs by key images
  std::vector<size_t> ins_order(new_ptx.tx.vin.size());
  for (size_t n = 0; n < ins_order.size(); ++n)
    ins_order[n] = n;
  std::sort(ins_order.begin(), ins_order.end(), [&](size_t i0, size_t i1) {
    const cryptonote::txin_to_key &tk0 = boost::get<cryptonote::txin_to_key>(new_ptx.tx.vin[i0]);
    const cryptonote::txin_to_key &tk1 = boost::get<cryptonote::txin_to_key>(new_ptx.tx.vin[i1]);
    return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
  });
  tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
    std::swap(new_ptx.tx.vin[i0], new_ptx.tx.vin[i1]);
    std::swap(new_ptx.tx.rct_signatures.p.pseudoOuts[i0], new_ptx.tx.rct_signatures.p.pseudoOuts[i1]);
    std::swap(new_mixRing[i0], new_mixRing[i1]);
  });

  // merge tx keys
  std::vector<uint8_t> extra = old_ptx.tx.extra, unparsed;
  std::vector<cryptonote::tx_extra_field> fields;
  cryptonote::parse_tx_extra(extra, fields, &unparsed);

  crypto::public_key tx_key = cryptonote::get_tx_pub_key_from_extra(ptx.tx);
  cryptonote::remove_field_from_tx_extra(extra, typeid(cryptonote::tx_extra_pub_key));
  cryptonote::add_tx_pub_key_to_extra(extra, tx_key);

  std::vector<crypto::public_key> old_additional_tx_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(old_ptx.tx);
  CHECK_AND_ASSERT_THROW_MES(old_additional_tx_pub_keys.size() == old_ptx.tx.vout.size(), "Bad number of additional tx pub keys");
  std::vector<crypto::public_key> additional_tx_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(ptx.tx);
  CHECK_AND_ASSERT_THROW_MES(additional_tx_pub_keys.size() == ptx.tx.vout.size(), "Bad number of additional tx pub keys");
  std::copy(additional_tx_pub_keys.begin(), additional_tx_pub_keys.end(), std::back_inserter(old_additional_tx_pub_keys));

  new_ptx.additional_tx_keys = old_ptx.additional_tx_keys;
  std::copy(ptx.additional_tx_keys.begin(), ptx.additional_tx_keys.end(), std::back_inserter(new_ptx.additional_tx_keys));

  // create N output duplicates, each with a different index, so they can be shuffled
  CHECK_AND_ASSERT_THROW_MES(multiuser_txs.m_vouts.size() == old_ptx.tx.vout.size(), "Invalid m_vouts size");
  CHECK_AND_ASSERT_THROW_MES(ptx.construction_data.splitted_dsts.size() == ptx.tx.vout.size(), "Invalid public setup dests size");
  vouts.clear();
  for (size_t out_idx = 0; out_idx < ptx.tx.vout.size(); ++out_idx)
  {
    vouts.push_back({});
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.tx.rct_signatures.ecdhInfo.size(), "Invalid ecdhInfo size");
    rct::ecdhTuple base_ecdh_info = new_ptx.tx.rct_signatures.ecdhInfo[out_idx + output_offset];
    crypto::key_derivation derivation;
    crypto::generate_key_derivation(ptx.construction_data.splitted_dsts[out_idx].addr.m_view_public_key, new_ptx.additional_tx_keys[out_idx + output_offset], derivation);
    crypto::secret_key original_scalar1;
    m_account.get_device().derivation_to_scalar(derivation, out_idx + output_offset, original_scalar1);
    rct::ecdhDecode(base_ecdh_info, rct::sk2rct(original_scalar1), new_ptx.tx.rct_signatures.type == rct::RCTTypeBulletproof2);
    for (int output_index = 0; output_index < BULLETPROOF_MAX_OUTPUTS; ++output_index)
    {
      cryptonote::tx_out vout;
      crypto::secret_key tx_key, amount_key;
      cryptonote::create_output(ptx.construction_data.splitted_dsts[out_idx], output_index, vout, tx_key, amount_key, m_account.get_device());
      rct::ecdhTuple ecdh_info = base_ecdh_info;
      rct::ecdhEncode(ecdh_info, rct::sk2rct(amount_key), new_ptx.tx.rct_signatures.type == rct::RCTTypeBulletproof2);
      rct::key outPk_mask;
      rct::addKeys2(outPk_mask, base_ecdh_info.mask, base_ecdh_info.amount, rct::H);
      rct::Bulletproof bp = rct::bulletproof_PROVE(ptx.construction_data.splitted_dsts[out_idx].amount, base_ecdh_info.mask);
      vouts.back().push_back({vout, tx_key, ecdh_info, outPk_mask, bp});
    }
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.tx.vout.size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < vouts.back().size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.additional_tx_keys.size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < old_additional_tx_pub_keys.size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.tx.rct_signatures.ecdhInfo.size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.tx.rct_signatures.outPk.size(), "Too many outs");
    CHECK_AND_ASSERT_THROW_MES(out_idx + output_offset < new_ptx.tx.rct_signatures.p.bulletproofs.size(), "Too many outs");
    new_ptx.tx.vout[out_idx + output_offset] = std::get<0>(vouts.back()[out_idx + output_offset]);
    new_ptx.additional_tx_keys[out_idx + output_offset] = std::get<1>(vouts.back()[out_idx + output_offset]);
    new_ptx.tx.rct_signatures.ecdhInfo[out_idx + output_offset] = std::get<2>(vouts.back()[out_idx + output_offset]);
    crypto::secret_key_to_public_key(std::get<1>(vouts.back()[out_idx + output_offset]), old_additional_tx_pub_keys[out_idx + output_offset]);
    new_ptx.tx.rct_signatures.outPk[out_idx + output_offset].mask = std::get<3>(vouts.back()[out_idx + output_offset]);
    new_ptx.tx.rct_signatures.p.bulletproofs[out_idx + output_offset] = std::get<4>(vouts.back()[out_idx + output_offset]);

    std::vector<std::tuple<cryptonote::tx_out, crypto::secret_key, rct::ecdhTuple, rct::key, rct::Bulletproof, crypto::public_key>> v;
    for (size_t i = 0; i < vouts.back().size(); ++i)
    {
      const auto &e = vouts.back()[i];
      crypto::public_key pkey;
      crypto::secret_key_to_public_key(std::get<1>(e), pkey);
      v.push_back(std::make_tuple(std::get<0>(e), std::get<1>(e), std::get<2>(e), std::get<3>(e), std::get<4>(e), pkey));
    }
    multiuser_txs.m_vouts.push_back(v);

    // clear out some private information
    new_ptx.selected_transfers.clear();
    new_ptx.dust = 0;
    new_ptx.fee = 0;
    new_ptx.dust_added_to_fee = false;
    new_ptx.change_dts = {};
    new_ptx.key_images.clear();
    new_ptx.dests.clear();
    new_ptx.multisig_sigs.clear();
    new_ptx.construction_data = {};
    new_ptx.tx_key = crypto::null_skey;
    if (!disclose)
    {
      for (auto &e: multiuser_txs.m_vouts.back())
        std::get<1>(e) = crypto::null_skey;
    }
  }

  // shuffle the array, then vouts, selecting from the array
  std::vector<size_t> outs_order(new_ptx.tx.vout.size());
  for (size_t n = 0; n < outs_order.size(); ++n)
    outs_order[n] = n;
    std::shuffle(outs_order.begin(), outs_order.end(), std::default_random_engine(crypto::rand<unsigned>()));
    tools::apply_permutation(outs_order, [&] (size_t i0, size_t i1) {
    std::swap(new_ptx.tx.vout[i0], new_ptx.tx.vout[i1]);
    std::swap(new_ptx.tx.rct_signatures.outPk[i0], new_ptx.tx.rct_signatures.outPk[i1]);
    std::swap(new_ptx.tx.rct_signatures.ecdhInfo[i0], new_ptx.tx.rct_signatures.ecdhInfo[i1]);
    std::swap(multiuser_txs.m_vouts[i0], multiuser_txs.m_vouts[i1]);
    std::swap(new_ptx.additional_tx_keys[i0], new_ptx.additional_tx_keys[i1]);
  });
  CHECK_AND_ASSERT_THROW_MES(multiuser_txs.m_vouts.size() == new_ptx.tx.vout.size(), "Invalid m_vouts size");
  CHECK_AND_ASSERT_THROW_MES(new_ptx.additional_tx_keys.size() == new_ptx.tx.vout.size(), "Invalid additional_tx_keys size");
  for (size_t i = 0; i < new_ptx.tx.vout.size(); ++i)
  {
    CHECK_AND_ASSERT_THROW_MES(multiuser_txs.m_vouts[i].size() > i, "Not enough m_vouts");
    new_ptx.tx.vout[i] = std::get<0>(multiuser_txs.m_vouts[i][i]);
    CHECK_AND_ASSERT_THROW_MES(old_additional_tx_pub_keys.size() > i, "Not enough additional tx keys");
    old_additional_tx_pub_keys[i] = std::get<5>(multiuser_txs.m_vouts[i][i]);
    new_ptx.additional_tx_keys[i] = std::get<1>(multiuser_txs.m_vouts[i][i]);
    new_ptx.tx.rct_signatures.ecdhInfo[i] = std::get<2>(multiuser_txs.m_vouts[i][i]);
    new_ptx.tx.rct_signatures.outPk[i].mask = std::get<3>(multiuser_txs.m_vouts[i][i]);
    new_ptx.tx.rct_signatures.p.bulletproofs[i] = std::get<4>(multiuser_txs.m_vouts[i][i]);
  }

  cryptonote::remove_field_from_tx_extra(extra, typeid(cryptonote::tx_extra_additional_pub_keys));
  cryptonote::add_additional_tx_pub_keys_to_extra(extra, old_additional_tx_pub_keys);
  new_ptx.tx.extra = extra;

  multiuser_txs.m_ptx = new_ptx;
  multiuser_txs.m_mixRing = new_mixRing;

  MDEBUG("new ptx has " << multiuser_txs.m_ptx.tx.vin.size() << " vins");
  MDEBUG("new ptx has " << multiuser_txs.m_mixRing.size() << " mixRing entries");
  MDEBUG("new ptx has " << multiuser_txs.m_ptx.tx.vout.size() << " vouts");
  MDEBUG("new ptx has " << multiuser_txs.m_ptx.tx.rct_signatures.p.pseudoOuts.size() << " pseudoOuts");
  MDEBUG("new ptx has " << multiuser_txs.m_ptx.tx.rct_signatures.outPk.size() << " outPks");
  MDEBUG("new ptx has " << multiuser_txs.m_ptx.tx.rct_signatures.ecdhInfo.size() << " ecdhInfos");

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_multiuser_tx(multiuser_tx_set &mtx)
{
  cryptonote::transaction &tx = mtx.m_ptx.tx;
  THROW_WALLET_EXCEPTION_IF(!is_suitable_for_multiuser(tx), error::wallet_internal_error,
      "Transaction is not suitable for multiuser");

  rct::rctSig &rv = tx.rct_signatures;
  bool found = false;
  multiuser_private_setup private_setup;
  multiuser_public_setup public_setup;
  for (const std::string &setup: mtx.m_setup)
  {
    bool ours;
    if (load_multiuser_setup(setup, private_setup, public_setup, ours) && ours)
    {
      found = true;
      break;
    }
  }
  THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error, "original multiuser private setup not found");
  const rct::multiuser_out &original_muout = private_setup.muout;

  hw::device &hwdev =  m_account.get_device();
  const std::vector<crypto::public_key> actual_additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(tx);

  // check our ins are present
  for (const auto &pin: private_setup.vin)
  {
    CHECKED_GET_SPECIFIC_VARIANT(pin, const cryptonote::txin_to_key, pink, false);
    auto it = std::find_if(tx.vin.begin(), tx.vin.end(), [&pink](const cryptonote::txin_v &in){
      if (in.type() != typeid(cryptonote::txin_to_key))
        return false;
      const cryptonote::txin_to_key &ink = boost::get<cryptonote::txin_to_key>(in);
      if (pink.amount != ink.amount)
        return false;
      if (pink.key_offsets != ink.key_offsets)
        return false;
      if (pink.k_image != ink.k_image)
        return false;
      return true;
    });
    THROW_WALLET_EXCEPTION_IF(it == tx.vin.end(), error::wallet_internal_error,
        "One of our inputs to the original multiuser transaction was not found in the final transaction to be signed");
  }

  auto same_txout = [](const cryptonote::tx_out &out0, const cryptonote::tx_out &out1)
  {
    CHECKED_GET_SPECIFIC_VARIANT(out0.target, const cryptonote::txout_to_key, out0k, false);
    CHECKED_GET_SPECIFIC_VARIANT(out1.target, const cryptonote::txout_to_key, out1k, false);
    return out0.amount == out1.amount && out0k.key == out1k.key;
  };

  // check our outs are present in the shuffled outs
  THROW_WALLET_EXCEPTION_IF(tx.vout.size() != actual_additional_tx_keys.size(), error::wallet_internal_error, "Wrong number of additional tx keys");
  std::vector<bool> our_outputs(tx.vout.size(), false);
  for (size_t i = 0; i < private_setup.vout.size(); ++i)
  {
    // for every out we generated, we check that it or one of its siblings (same out data,
    // but generated using a different index) is present in the tx
    for (size_t j = 0; j < private_setup.vout[i].size(); ++j)
      for (size_t k = 0; k < tx.vout.size(); ++k)
        if (same_txout(std::get<0>(private_setup.vout[i][j]), tx.vout[k]))
        {
          crypto::public_key pkey;
          crypto::secret_key_to_public_key(std::get<1>(private_setup.vout[i][j]), pkey);
          if (pkey == actual_additional_tx_keys[k])
          {
            THROW_WALLET_EXCEPTION_IF(our_outputs[k], error::wallet_internal_error, "One output matched more than one of our original outputs");
            our_outputs[k] = true;
            goto found;
          }
        }

    THROW_WALLET_EXCEPTION(error::wallet_internal_error,
        "One of our outputs to the original multiuser transaction was not found in the final transaction to be signed");

found:;
  }

  // check claimed destinations are what they claim to be
  std::unordered_map<cryptonote::account_public_address, uint64_t> third_party_payments;
  for (const auto &setup: mtx.m_setup)
  {
    multiuser_private_setup prv;
    multiuser_public_setup pub;
    bool ours;
    THROW_WALLET_EXCEPTION_IF(!load_multiuser_setup(setup, prv, pub, ours), error::wallet_internal_error, "Invalid public setup");
    if (ours)
      continue;

    std::vector<bool> output_used(tx.vout.size(), false);
    for (const auto &dest: pub.dests)
    {
      uint64_t received = 0;
      crypto::key_derivation derivation;
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(dest.addr.m_view_public_key, mtx.m_ptx.tx_key, derivation),
          error::wallet_internal_error, "Failed to generate key derivation from supplied parameters");
      std::vector<crypto::key_derivation> additional_derivations;
      additional_derivations.resize(mtx.m_ptx.additional_tx_keys.size());
      for (size_t i = 0; i < mtx.m_ptx.additional_tx_keys.size(); ++i)
        THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(dest.addr.m_view_public_key, mtx.m_ptx.additional_tx_keys[i], additional_derivations[i]),
          error::wallet_internal_error, "Failed to generate key derivation from supplied parameters");

      for (size_t n = 0; n < tx.vout.size(); ++n)
      {
        if (our_outputs[n] || output_used[n])
          continue;

        const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
        if (!out_key)
          continue;

        crypto::public_key derived_out_key;
        bool r = hwdev.derive_public_key(derivation, n, dest.addr.m_spend_public_key, derived_out_key);
        THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
        bool found = out_key->key == derived_out_key;
        crypto::key_derivation found_derivation = derivation;
        if (!found && n < additional_derivations.size())
        {
          r = hwdev.derive_public_key(additional_derivations[n], n, dest.addr.m_spend_public_key, derived_out_key);
          THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
          found = out_key->key == derived_out_key;
          found_derivation = additional_derivations[n];
        }

        if (!found)
          continue;

        uint64_t amount;
        crypto::secret_key scalar1;
        hwdev.derivation_to_scalar(found_derivation, n, scalar1);
        rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
        hwdev.ecdhDecode(ecdh_info, rct::sk2rct(scalar1), tx.rct_signatures.type == rct::RCTTypeBulletproof2);
        const rct::key C = tx.rct_signatures.outPk[n].mask;
        rct::key Ctmp;
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.mask.bytes) != 0, error::wallet_internal_error, "Bad ECDH input mask");
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.amount.bytes) != 0, error::wallet_internal_error, "Bad ECDH input amount");
        rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
        if (rct::equalKeys(C, Ctmp))
          received += rct::h2d(ecdh_info.amount);

        THROW_WALLET_EXCEPTION_IF(third_party_payments[dest.addr] > std::numeric_limits<uint64_t>::max() - received,
            error::wallet_internal_error, "Amount overflow");

        third_party_payments[dest.addr] += received;
        output_used[n] = true;
      }

      THROW_WALLET_EXCEPTION_IF(received < dest.amount, error::wallet_internal_error,
          "Transaction pays less than claimed (claims " + cryptonote::print_money(dest.amount) + ", pays " + cryptonote::print_money(received));
    }
  }

  // check conditions
  for (const auto &cond: public_setup.conditions)
  {
    THROW_WALLET_EXCEPTION_IF(third_party_payments[cond.addr] < cond.amount, error::wallet_internal_error,
        "Third parties did not pay at least " + cryptonote::print_money(cond.amount) + " to " + cryptonote::get_account_address_as_str(m_nettype, cond.is_subaddress, cond.addr) + ", only " + cryptonote::print_money(third_party_payments[cond.addr]));
  }

  const size_t n_inputs = tx.vin.size();
  CHECK_AND_ASSERT_MES(original_muout.a.size() <= n_inputs, false, "Inconsistent a size");
  CHECK_AND_ASSERT_MES(original_muout.index.size() <= n_inputs, false, "Inconsistent index size");

  const cryptonote::account_keys& keys = get_account().get_keys();
  rct::ctkeyV inSk(n_inputs);
  std::vector<bool> owned(n_inputs, false);
  rct::multiuser_out muout;
  muout.a.resize(n_inputs, rct::zero());
  muout.index.resize(n_inputs, 0);
  for (size_t i = 0; i < n_inputs; ++i)
  {
    THROW_WALLET_EXCEPTION_IF(tx.vin[i].type() != typeid(cryptonote::txin_to_key),
        error::wallet_internal_error, "multiuser tx vin has unexpected type: " + std::string(tx.vin[i].type().name()));

    const cryptonote::txin_to_key &in = boost::get<cryptonote::txin_to_key>(tx.vin[i]);
    for (const transfer_details &td: m_transfers)
    {
      if (td.m_key_image_known && td.m_key_image == in.k_image)
      {
        MDEBUG("we can sign vin " << i);
        crypto::key_image img;
        cryptonote::keypair in_ephemeral;
        const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
        const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
        THROW_WALLET_EXCEPTION_IF(!generate_key_image_helper(keys, m_subaddresses, td.get_public_key(), tx_pub_key, additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, img, hwdev),
            error::wallet_internal_error, "Failed to generate key image");
        inSk[i].dest = rct::sk2rct(in_ephemeral.sec);
        inSk[i].mask = td.m_mask;

        // work out which original input it was before it got sorted
        size_t original_i;
        THROW_WALLET_EXCEPTION_IF(original_muout.a.size() != private_setup.vin.size(), error::wallet_internal_error, "Unexpected a/vin size");
        for (original_i = 0; original_i < private_setup.vin.size(); ++original_i)
        {
          if (private_setup.vin[original_i].type() != typeid(cryptonote::txin_to_key))
            continue;
          const cryptonote::txin_to_key &ink = boost::get<cryptonote::txin_to_key>(private_setup.vin[original_i]);
          if (ink.k_image == in.k_image)
            break;
        }
        CHECK_AND_ASSERT_THROW_MES(original_i < private_setup.vin.size(), "vin not found");

        CHECK_AND_ASSERT_THROW_MES(original_i < original_muout.a.size(), "Invalid offset in a");
        muout.a[i] = original_muout.a[original_i];
        CHECK_AND_ASSERT_THROW_MES(original_i < original_muout.index.size(), "Invalid offset in index");
        muout.index[i] = original_muout.index[original_i];
        owned[i] = true;
        break;
      }
    }
  }

  // check sundry
  THROW_WALLET_EXCEPTION_IF(mtx.m_ptx.tx.unlock_time != public_setup.unlock_time, error::wallet_internal_error,
      "The transaction has an unlock_time which differs from our own");

  mtx.m_building = false;
  rv.message = rct::hash2rct(cryptonote::get_transaction_prefix_hash(tx));
  rv.mixRing = mtx.m_mixRing;
  rv.p.MGs.resize(n_inputs);
  if (!rct::signMultiuser(rv, inSk, owned, muout, hwdev))
  {
    MERROR("Failed to sign multiuser tx");
    return false;
  }
  return true;
}

}
