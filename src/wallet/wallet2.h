// Copyright (c) 2014-2015, The Monero Project
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

#pragma once

#include <memory>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <atomic>

#include "include_base_utils.h"
#include "cryptonote_core/account.h"
#include "cryptonote_core/account_boost_serialization.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/chacha8.h"
#include "crypto/hash.h"

#include "wallet_errors.h"

#include <iostream>
#define DEFAULT_TX_SPENDABLE_AGE                               10
#define WALLET_RCP_CONNECTION_TIMEOUT                          200000

namespace tools
{
  class i_wallet2_callback
  {
  public:
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const cryptonote::transaction& tx, size_t out_index) {}
    virtual void on_money_spent(uint64_t height, const cryptonote::transaction& in_tx, size_t out_index, const cryptonote::transaction& spend_tx) {}
    virtual void on_skip_transaction(uint64_t height, const cryptonote::transaction& tx) {}
  };

  struct tx_dust_policy
  {
    uint64_t dust_threshold;
    bool add_to_fee;
    cryptonote::account_public_address addr_for_dust;

    tx_dust_policy(uint64_t a_dust_threshold = 0, bool an_add_to_fee = true, cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address())
      : dust_threshold(a_dust_threshold)
      , add_to_fee(an_add_to_fee)
      , addr_for_dust(an_addr_for_dust)
    {
    }
  };

  namespace detail
  {
    class output_split_strategy;
  };

  class wallet2
  {
    wallet2(const wallet2&) : m_run(true), m_callback(0), m_testnet(false), m_always_confirm_transfers (false) {};
  public:
    wallet2(bool testnet = false, bool restricted = false) : m_run(true), m_callback(0), m_testnet(testnet), m_restricted(restricted), is_old_file_format(false) {};
    struct transfer_details
    {
      uint64_t m_block_height;
      cryptonote::transaction m_tx;
      size_t m_internal_output_index;
      uint64_t m_global_output_index;
      bool m_spent;
      crypto::key_image m_key_image; //TODO: key_image stored twice :(

      uint64_t amount() const { return m_tx.vout[m_internal_output_index].amount; }
    };

    struct payment_details
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount;
      uint64_t m_block_height;
      uint64_t m_unlock_time;
    };

    struct unconfirmed_transfer_details
    {
      cryptonote::transaction m_tx;
      uint64_t m_change;
      time_t m_sent_time;
    };

    typedef std::vector<transfer_details> transfer_container;
    typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

    struct pending_tx
    {
      cryptonote::transaction tx;
      uint64_t dust, fee;
      cryptonote::tx_destination_entry change_dts;
      std::list<transfer_container::iterator> selected_transfers;
      std::string key_images;
    };

    struct keys_file_data
    {
      crypto::chacha8_iv iv;
      std::string account_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
      END_SERIALIZE()
    };

    struct TX {
      std::list<transfer_container::iterator> selected_transfers;
      std::vector<cryptonote::tx_destination_entry> dsts;
      cryptonote::transaction tx;
      pending_tx ptx;
      size_t bytes;

      void add(const cryptonote::account_public_address &addr, uint64_t amount) {
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &addr, sizeof(addr)); });
        if (i == dsts.end())
          dsts.push_back(cryptonote::tx_destination_entry(amount,addr));
        else
          i->amount += amount;
      }
    };

    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_        Name of wallet file
     * \param  password       Password of wallet file
     * \param  recovery_param If it is a restore, the recovery key
     * \param  recover        Whether it is a restore
     * \param  two_random     Whether it is a non-deterministic wallet
     * \return                The secret key of the generated wallet
     */
    crypto::secret_key generate(const std::string& wallet, const std::string& password,
      const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false,
      bool two_random = false);
    /*!
     * \brief Creates a watch only wallet from a public address and a view secret key.
     * \param  wallet_        Name of wallet file
     * \param  password       Password of wallet file
     * \param  viewkey        view secret key
     */
    void generate(const std::string& wallet, const std::string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& viewkey = crypto::secret_key());
    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const std::string& wallet_name, const std::string& password);
    void write_watch_only_wallet(const std::string& wallet_name, const std::string& password);
    void load(const std::string& wallet, const std::string& password);
    void store();

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const std::string& password) const;
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    // upper_transaction_size_limit as defined below is set to 
    // approximately 125% of the fixed minimum allowable penalty
    // free block size. TODO: fix this so that it actually takes
    // into account the current median block size rather than
    // the minimum block size.
    void init(const std::string& daemon_address = "http://localhost:8080", uint64_t upper_transaction_size_limit = ((CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 125) / 100) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
    bool deinit();

    void stop() { m_run.store(false, std::memory_order_relaxed); }

    i_wallet2_callback* callback() const { return m_callback; }
    void callback(i_wallet2_callback* callback) { m_callback = callback; }

    /*!
     * \brief Checks if deterministic wallet
     */
    bool is_deterministic() const;
    bool get_seed(std::string& electrum_words) const;
    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);
    /*!
     * \brief Tells if the wallet file is deprecated.
     */
    bool is_deprecated() const;
    void refresh();
    void refresh(uint64_t start_height, size_t & blocks_fetched);
    void refresh(uint64_t start_height, size_t & blocks_fetched, bool& received_money);
    bool refresh(size_t & blocks_fetched, bool& received_money, bool& ok);

    bool testnet() const { return m_testnet; }
    bool restricted() const { return m_restricted; }
    bool watch_only() const { return m_watch_only; }

    uint64_t balance() const;
    uint64_t unlocked_balance() const;
    uint64_t unlocked_dust_balance(const tx_dust_policy &dust_policy) const;
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, size_t fake_outputs_count, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, const detail::output_split_strategy &destination_split_strategy, const tx_dust_policy& dust_policy);
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, size_t fake_outputs_count, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, const detail::output_split_strategy &destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx& ptx);
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, size_t fake_outputs_count, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra);
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, size_t fake_outputs_count, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx& ptx);
    void transfer_dust(size_t num_outputs, uint64_t unlock_time, uint64_t needed_fee, const detail::output_split_strategy &destination_split_strategy, const tx_dust_policy& dust_policy, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx);
    void transfer_selected(const std::vector<cryptonote::tx_destination_entry>& dsts, const std::list<transfer_container::iterator> selected_transfers, size_t fake_outputs_count,
      uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, const detail::output_split_strategy &destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx &ptx);

    void commit_tx(pending_tx& ptx_vector);
    void commit_tx(std::vector<pending_tx>& ptx_vector);
    std::vector<pending_tx> create_transactions(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, const uint64_t fee, const std::vector<uint8_t> extra);
    std::vector<wallet2::pending_tx> create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, const uint64_t fee_UNUSED, const std::vector<uint8_t> extra, bool add_decoy_outputs = true, bool add_amount_noise = true, bool reorder_transactions = true, bool resplit_outputs = true);
    std::vector<pending_tx> create_dust_sweep_transactions();
    bool check_connection();
    void get_transfers(wallet2::transfer_container& incoming_transfers) const;
    void get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height = 0) const;
    void get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height) const;
    uint64_t get_blockchain_current_height() const { return m_local_bc_height; }
    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      if(ver < 5)
        return;
      a & m_blockchain;
      a & m_transfers;
      a & m_account_public_address;
      a & m_key_images;
      if(ver < 6)
        return;
      a & m_unconfirmed_txs;
      if(ver < 7)
        return;
      a & m_payments;
    }

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    /*!
     * \brief  Check if wallet file path is valid format
     * \param  file_path      Wallet file path
     * \return                Whether path is valid format
     */
    static bool wallet_valid_path_format(const std::string& file_path);

    static bool parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);

    static std::vector<std::string> addresses_from_url(const std::string& url, bool& dnssec_valid);

    static std::string address_from_txt_record(const std::string& s);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }

  private:
    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \param  watch_only     true to save only view key, false to save both spend and view keys
     * \return                Whether it was successful.
     */
    bool store_keys(const std::string& keys_file_name, const std::string& password, bool watch_only = false);
    /*!
     * \brief Load wallet information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    void load_keys(const std::string& keys_file_name, const std::string& password);
    void process_new_transaction(const cryptonote::transaction& tx, uint64_t height);
    void process_new_blockchain_entry(const cryptonote::block& b, cryptonote::block_complete_entry& bche, crypto::hash& bl_id, uint64_t height);
    void detach_blockchain(uint64_t height);
    void get_short_chain_history(std::list<crypto::hash>& ids) const;
    bool is_tx_spendtime_unlocked(uint64_t unlock_time) const;
    bool is_transfer_unlocked(const transfer_details& td) const;
    bool clear();
    void pull_blocks(uint64_t start_height, size_t& blocks_added);
    uint64_t select_transfers(uint64_t needed_money, bool add_dust, uint64_t dust, std::list<transfer_container::iterator>& selected_transfers);
    bool prepare_file_names(const std::string& file_path);
    void process_unconfirmed(const cryptonote::transaction& tx);
    void add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t change_amount);
    void generate_genesis(cryptonote::block& b);
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    size_t pick_tx_size_target() const;
    void log_txes(const std::vector<TX> &txes, const char *msg) const;
    void check_txes_match_request(const std::vector<cryptonote::tx_destination_entry> &dsts, const std::vector<TX> &txes) const;

    cryptonote::account_base m_account;
    std::string m_daemon_address;
    std::string m_wallet_file;
    std::string m_keys_file;
    epee::net_utils::http::http_simple_client m_http_client;
    std::vector<crypto::hash> m_blockchain;
    std::atomic<uint64_t> m_local_bc_height; //temporary workaround
    std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;

    transfer_container m_transfers;
    payment_container m_payments;
    std::unordered_map<crypto::key_image, size_t> m_key_images;
    cryptonote::account_public_address m_account_public_address;
    uint64_t m_upper_transaction_size_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value

    std::atomic<bool> m_run;

    i_wallet2_callback* m_callback;
    bool m_testnet;
    bool m_restricted;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool is_old_file_format; /*!< Whether the wallet file is of an old file format */
    bool m_watch_only; /*!< no spend key */
    bool m_always_confirm_transfers;
  };
}
BOOST_CLASS_VERSION(tools::wallet2, 7)

namespace boost
{
  namespace serialization
  {
    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_block_height;
      a & x.m_global_output_index;
      a & x.m_internal_output_index;
      a & x.m_tx;
      a & x.m_spent;
      a & x.m_key_image;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet2::unconfirmed_transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_change;
      a & x.m_sent_time;
      a & x.m_tx;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet2::payment_details& x, const boost::serialization::version_type ver)
    {
      a & x.m_tx_hash;
      a & x.m_amount;
      a & x.m_block_height;
      a & x.m_unlock_time;
    }
  }
}

namespace tools
{

  namespace detail
  {
    //----------------------------------------------------------------------------------------------------
    class output_split_strategy
    {
    public:
      virtual void operator() (const std::vector<cryptonote::tx_destination_entry>& dsts,
        const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
        std::vector<cryptonote::tx_destination_entry>& splitted_dsts, uint64_t& dust) const = 0;
    };
    //----------------------------------------------------------------------------------------------------
    class digit_split_strategy: public output_split_strategy
    {
    public:
      virtual void operator() (const std::vector<cryptonote::tx_destination_entry>& dsts,
        const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
        std::vector<cryptonote::tx_destination_entry>& splitted_dsts, uint64_t& dust) const
      {
        splitted_dsts.clear();
        dust = 0;

        BOOST_FOREACH(auto& de, dsts)
        {
          cryptonote::decompose_amount_into_digits(de.amount, dust_threshold,
            [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr)); },
            [&](uint64_t a_dust) { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr)); } );
        }

        cryptonote::decompose_amount_into_digits(change_dst.amount, dust_threshold,
          [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr)); },
          [&](uint64_t a_dust) { dust = a_dust; } );
      }
    };
    //----------------------------------------------------------------------------------------------------
    class digit_split_resplit_strategy: public output_split_strategy
    {
    private:
      static inline bool in_range(uint64_t x) { return x && x<=30; }

    public:
      digit_split_resplit_strategy(size_t passes = 1, size_t min_splits = 2, size_t max_splits = 3):
        passes(passes),
        min_splits(min_splits),
        max_splits(max_splits)
      {
      }

      virtual void operator() (const std::vector<cryptonote::tx_destination_entry>& dsts,
        const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
        std::vector<cryptonote::tx_destination_entry>& splitted_dsts, uint64_t& dust) const
      {
        splitted_dsts.clear();
        dust = 0;

        BOOST_FOREACH(auto& de, dsts)
        {
          cryptonote::decompose_amount_into_digits(de.amount, dust_threshold,
            [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr)); },
            [&](uint64_t a_dust) { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr)); } );
        }

        cryptonote::decompose_amount_into_digits(change_dst.amount, dust_threshold,
          [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr)); },
          [&](uint64_t a_dust) { dust = a_dust; } );

        // A second pass splits high value outputs in two or three different ones
        for (size_t n = 0; n < passes; ++n) // one pass
        {
          // sort higher amounts first
          std::sort(splitted_dsts.begin(), splitted_dsts.end(),
            [](const cryptonote::tx_destination_entry &e1, const cryptonote::tx_destination_entry &e2) { return e1.amount < e2.amount; } );
          std::vector<cryptonote::tx_destination_entry> resplitted_dsts;

          for (size_t i = 0; i < splitted_dsts.size(); ++i)
          {
            const cryptonote::tx_destination_entry &de = splitted_dsts[i];
            uint64_t amount = de.amount;
            if (amount >= max_splits * dust_threshold)
            {
              // determine leading digit(s) and exponent
              uint64_t e = dust_threshold / 100, d;
              while (!in_range(d = ((amount / (e *= 10)) % 100)));
              // we should get 10, 20, 30, 4, 5, 6, 7, 8, 9, which are small enough amounts
              // that can be split in a few integer parts

              // split in a few parts; this is done by assigning units of the leading digit(s)
              // into buckets, so we should get a distribution that's random while not being
              // too flat (since the head digits are small enough)
              uint64_t *parts = (uint64_t*)alloca(max_splits);
              size_t n_splits = min_splits + crypto::rand<size_t>() % (max_splits - min_splits + 1);
              for (size_t p = 0; p < n_splits; ++p)
                parts[p] = 0;
              for (uint64_t p = 0; p < d; ++p) // 10-90 iterations
                parts[crypto::rand<size_t>() % n_splits]++;
              for (size_t p = 0; p < n_splits; ++p)
                parts[p] *= e;

              std::string parts_string = "";
              for (size_t p = 0; p < n_splits; ++p)
                parts_string += (p ? ", " : "") + cryptonote::print_money(parts[p]);
              LOG_PRINT_L2("Splitting " << cryptonote::print_money(amount) << " (bucket " << d << ") into " << parts_string);

              for (size_t p = 0; p < n_splits; ++p)
              {
                cryptonote::decompose_amount_into_digits(parts[p], dust_threshold,
                  [&](uint64_t chunk) { resplitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr)); },
                  [&](uint64_t a_dust) { resplitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr)); } );
              }
            }
            else
            {
              LOG_PRINT_L2("Not splitting " << cryptonote::print_money(de.amount));
              resplitted_dsts.push_back(de);
            }
          }
          LOG_PRINT_L2("Resplitted " << splitted_dsts.size() << " outputs into " << resplitted_dsts.size() << " outputs");
          splitted_dsts = resplitted_dsts;
        }
      }

    private:
      size_t passes;
      size_t min_splits;
      size_t max_splits;
    };
    //----------------------------------------------------------------------------------------------------
    inline void null_split_strategy(const std::vector<cryptonote::tx_destination_entry>& dsts,
      const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
      std::vector<cryptonote::tx_destination_entry>& splitted_dsts, uint64_t& dust)
    {
      splitted_dsts = dsts;

      dust = 0;
      uint64_t change = change_dst.amount;
      if (0 < dust_threshold)
      {
        for (uint64_t order = 10; order <= 10 * dust_threshold; order *= 10)
        {
          uint64_t dust_candidate = change_dst.amount % order;
          uint64_t change_candidate = (change_dst.amount / order) * order;
          if (dust_candidate <= dust_threshold)
          {
            dust = dust_candidate;
            change = change_candidate;
          }
          else
          {
            break;
          }
        }
      }

      if (0 != change)
      {
        splitted_dsts.push_back(cryptonote::tx_destination_entry(change, change_dst.addr));
      }
    }
    //----------------------------------------------------------------------------------------------------
    inline void print_source_entry(const cryptonote::tx_source_entry& src)
    {
      std::string indexes;
      std::for_each(src.outputs.begin(), src.outputs.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });
      LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
    }
    //----------------------------------------------------------------------------------------------------
  }
}
