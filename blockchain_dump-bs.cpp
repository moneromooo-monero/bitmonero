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

#include "cryptonote_core/cryptonote_basic.h"
#include "cryptonote_core/blockchain_storage.h"
#include "common/command_line.h"
#include "version.h"

namespace po = boost::program_options;
using namespace epee; // log_space

using namespace cryptonote;

struct DumpContext {
  std::ofstream &f;
  size_t level;
  std::vector<std::string> close;

  DumpContext(std::ofstream &f): f(f), level(0) {}
};

template<typename S> static void start_compound(DumpContext &d, S key, bool array, bool print = false)
{
  if (print)
    LOG_PRINT_L0("Dumping " << key << "...");
  d.f << std::string(d.level*2, ' ');
  d.f << "\"" << key << "\": " << (array ? "[" : "{") << " \n";
  d.close.push_back(array ? "]" : "}");
  d.level++;
}

template<typename S> static void start_array(DumpContext &d, S key, bool print = false) { start_compound(d, key, true, print); }
template<typename S> static void start_struct(DumpContext &d, S key, bool print = false) { start_compound(d, key, false, print); }

static void end_compound(DumpContext &d)
{
  d.level--;
  d.f << std::string(d.level*2, ' ');
  d.f << d.close.back() << ",\n";
  d.close.pop_back();
}

template<typename S, typename T> static void write_pod(DumpContext &d, S key, const T &t)
{
  d.f << std::string(d.level*2, ' ');
  d.f << "\"" << key << "\": ";
  d.f << t;
  d.f << ",\n";
}

template<typename T> static void write_pod(DumpContext &d, const T &t)
{
  d.f << std::string(d.level*2, ' ');
  d.f << t;
  d.f << ",\n";
}

int main(int argc, char* argv[])
{
  uint32_t log_level = 0;
  uint64_t block_stop = 0;

  boost::filesystem::path default_data_path {tools::get_default_data_dir()};
  boost::filesystem::path default_testnet_data_path {default_data_path / "testnet"};
  boost::filesystem::path output_file_path;

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_output_file = {"output-file", "Specify output file", "", true};
  const command_line::arg_descriptor<uint32_t> arg_log_level  = {"log-level",  "", log_level};
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "Stop at block number", block_stop};
  const command_line::arg_descriptor<bool>     arg_testnet_on = {
    "testnet"
      , "Run on testnet."
      , false
  };


  command_line::add_arg(desc_cmd_sett, command_line::arg_data_dir, default_data_path.string());
  command_line::add_arg(desc_cmd_sett, command_line::arg_testnet_data_dir, default_testnet_data_path.string());
  command_line::add_arg(desc_cmd_sett, arg_output_file);
  command_line::add_arg(desc_cmd_sett, arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_block_stop);

  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << CRYPTONOTE_NAME << " v" << MONERO_VERSION_FULL << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  log_level    = command_line::get_arg(vm, arg_log_level);
  block_stop = command_line::get_arg(vm, arg_block_stop);

  log_space::get_set_log_detalisation_level(true, log_level);
  log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);
  LOG_PRINT_L0("Starting...");
  LOG_PRINT_L0("Setting log level = " << log_level);

  bool opt_testnet = command_line::get_arg(vm, arg_testnet_on);

  std::string m_config_folder;

  auto data_dir_arg = opt_testnet ? command_line::arg_testnet_data_dir : command_line::arg_data_dir;
  m_config_folder = command_line::get_arg(vm, data_dir_arg);

  if (command_line::has_arg(vm, arg_output_file))
    output_file_path = boost::filesystem::path(command_line::get_arg(vm, arg_output_file));
  else
    output_file_path = boost::filesystem::path(m_config_folder) / "dump" / "blockchain.json";
  LOG_PRINT_L0("Export output file: " << output_file_path.string());

  const boost::filesystem::path dir_path = output_file_path.parent_path();
  if (!dir_path.empty())
  {
    if (boost::filesystem::exists(dir_path))
    {
      if (!boost::filesystem::is_directory(dir_path))
      {
        LOG_PRINT_RED_L0("dump directory path is a file: " << dir_path);
        return false;
      }
    }
    else
    {
      if (!boost::filesystem::create_directory(dir_path))
      {
        LOG_PRINT_RED_L0("Failed to create directory " << dir_path);
        return false;
      }
    }
  }

  std::ofstream raw_data_file;
  raw_data_file.open(output_file_path.string(), std::ios_base::out | std::ios::trunc);
  if (raw_data_file.fail())
    return false;


  // If we wanted to use the memory pool, we would set up a fake_core.

  blockchain_storage* core_storage = NULL;
  tx_memory_pool m_mempool(*core_storage); // is this fake anyway? just passing in NULL! so m_mempool can't be used anyway, right?
  core_storage = new blockchain_storage(m_mempool);

  //blockchain_storage* core_storage = new blockchain_storage(NULL);
  LOG_PRINT_L0("Initializing source blockchain (in-memory database)");
  r = core_storage->init(m_config_folder, opt_testnet);

  CHECK_AND_ASSERT_MES(r, false, "Failed to initialize source blockchain storage");
  LOG_PRINT_L0("Source blockchain storage initialized OK");
  LOG_PRINT_L0("Dumping blockchain...");

  DumpContext d(raw_data_file);

  start_struct(d,"blockchain");
    uint64_t height = core_storage->get_current_blockchain_height();
    write_pod(d, "height", height);
    start_array(d,"blockids", true);
      for (uint64_t h = 0; h < height; ++h)
        write_pod(d,core_storage->get_block_id_by_height(h));
    end_compound(d);
    start_array(d,"txids", true);
    {
      std::vector<crypto::hash> txids;
      core_storage->for_all_transactions([&txids](const crypto::hash &hash, const cryptonote::transaction &tx)->bool{txids.push_back(hash); return true;});
      std::sort(txids.begin(), txids.end(),
        [](const crypto::hash &txid0, const crypto::hash &txid1) {return memcmp(txid0.data, txid1.data, sizeof(crypto::hash::data)) < 0;});
      for (size_t n = 0; n < txids.size(); ++n)
        write_pod(d, txids[n]);
    }
    end_compound(d);
    start_struct(d,"transactions", true);
    {
      for (uint64_t h = 0; h < height; ++h)
      {
        start_array(d, boost::lexical_cast<std::string>(h));
          std::list<cryptonote::block> blocks;
          std::list<cryptonote::transaction> transactions, miner_tx;
          core_storage->get_blocks(h, 1, blocks, transactions);
          if (blocks.size() != 1)
            throw std::string("Expected 1 block at height ") + boost::lexical_cast<std::string>(h);
          crypto::hash txid = cryptonote::get_transaction_hash(blocks.front().miner_tx);
          write_pod(d, string_tools::pod_to_hex(txid).c_str(), obj_to_json_str(blocks.front().miner_tx));
          std::vector<std::pair<crypto::hash, cryptonote::transaction>> txes;
          for (std::list<cryptonote::transaction>::iterator i = transactions.begin(); i != transactions.end(); ++i)
            txes.push_back(std::make_pair(cryptonote::get_transaction_hash(*i), *i));
          std::sort(txes.begin(), txes.end(),
            [](const std::pair<crypto::hash, cryptonote::transaction> &tx0, const std::pair<crypto::hash, cryptonote::transaction> &tx1) {return memcmp(tx0.first.data, tx1.first.data, sizeof(crypto::key_image::data)) < 0;});
          for (std::vector<std::pair<crypto::hash, cryptonote::transaction>>::iterator i = txes.begin(); i != txes.end(); ++i)
          {
            write_pod(d, string_tools::pod_to_hex((*i).first).c_str(), obj_to_json_str((*i).second));
          }
        end_compound(d);
      }
    }
    end_compound(d);
    start_struct(d,"blocks", true);
    {
      std::vector<crypto::hash> blockids;
      core_storage->for_all_blocks([&](uint64_t height, const crypto::hash &hash, const cryptonote::block &b)->bool{
         start_struct(d, boost::lexical_cast<std::string>(height));
           write_pod(d, "hash", string_tools::pod_to_hex(hash));
           cryptonote::block block = b;
           write_pod(d, "block", obj_to_json_str(block));
         end_compound(d);
         return true;
      });
    }
    end_compound(d);
    start_array(d,"key_images", true);
    {
      std::vector<crypto::key_image> key_images;
      core_storage->for_all_key_images([&key_images](const crypto::key_image &k_image)->bool{key_images.push_back(k_image); return true;});
      std::sort(key_images.begin(), key_images.end(),
        [](const crypto::key_image &k0, const crypto::key_image &k1) {return memcmp(k0.data, k1.data, sizeof(crypto::key_image::data)) < 0;});
      for (size_t n = 0; n < key_images.size(); ++n)
        write_pod(d,key_images[n]);
    }
    end_compound(d);
  end_compound(d);

  CHECK_AND_ASSERT_MES(r, false, "Failed to dump blockchain");

  if (raw_data_file.fail())
    return false;
  raw_data_file.flush();

  LOG_PRINT_L0("Blockchain dump OK");

  return 0;
}
