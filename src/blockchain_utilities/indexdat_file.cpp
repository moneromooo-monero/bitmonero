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

#include "indexdat_file.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;

using namespace cryptonote;
using namespace epee;

namespace
{
  std::string refresh_string = "\r                                    \r";
}



bool IndexdatFile::open_writer(const boost::filesystem::path& file_path, uint64_t block_stop)
{
  const boost::filesystem::path dir_path = file_path.parent_path();
  if (!dir_path.empty())
  {
    if (boost::filesystem::exists(dir_path))
    {
      if (!boost::filesystem::is_directory(dir_path))
      {
        MFATAL("export directory path is a file: " << dir_path);
        return false;
      }
    }
    else
    {
      if (!boost::filesystem::create_directory(dir_path))
      {
        MFATAL("Failed to create directory " << dir_path);
        return false;
      }
    }
  }

  m_raw_data_file = new std::ofstream();

  MINFO("creating file");

  m_raw_data_file->open(file_path.string(), std::ios_base::binary | std::ios_base::out | std::ios::trunc);
  if (m_raw_data_file->fail())
    return false;

  initialize_file(block_stop);

  return true;
}


bool IndexdatFile::initialize_file(uint64_t block_stop)
{
  return true;
}

template<typename T> void IndexdatFile::write(const T &t)
{
  *m_raw_data_file << std::string((const char*)&t, sizeof(T));
}

void IndexdatFile::write_tx(uint64_t height, const cryptonote::transaction &tx, bool miner_tx, uint64_t &n_rct)
{
  uint64_t n_ins = 0;
  uint64_t n_outs = 0;
  bool fake_rct = (miner_tx && tx.vin.size() == 1 && tx.vout.size() == 1 && tx.version == 2);
  if (!fake_rct)
  {
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      if (tx.vin[n].type() == typeid(cryptonote::txin_to_key))
      {
        const cryptonote::txin_to_key &tokey = boost::get<cryptonote::txin_to_key>(tx.vin[n]);
        if (tokey.amount == 0)
          n_ins += tokey.key_offsets.size();
      }
    }
    for (size_t n = 0; n < tx.vout.size(); ++n)
    {
      if (tx.vout[n].target.type() == typeid(cryptonote::txout_to_key))
      {
        if (tx.vout[n].amount == 0)
          n_outs++;
      }
    }
  }
  if (n_ins == 0 && n_outs == 0 && !fake_rct)
    return;

  write(height);
  if (fake_rct)
  {
    write((uint64_t)0);
    write((uint64_t)1);
    write(n_rct);
    ++n_rct;
  }
  else
  {
    write(n_ins);
    write(n_outs);
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      if (tx.vin[n].type() == typeid(cryptonote::txin_to_key))
      {
        const cryptonote::txin_to_key &tokey = boost::get<cryptonote::txin_to_key>(tx.vin[n]);
        if (tokey.amount == 0)
        {
          uint64_t idx = 0;
          for (size_t i = 0; i < tokey.key_offsets.size(); ++i)
          {
            idx += tokey.key_offsets[i];
            write(idx);
          }
        }
      }
    }
    for (size_t n = 0; n < tx.vout.size(); ++n)
    {
      if (tx.vout[n].target.type() == typeid(cryptonote::txout_to_key))
      {
        if (tx.vout[n].amount == 0)
        {
          write(n_rct);
          ++n_rct;
        }
      }
    }
  }
}

bool IndexdatFile::write_block(uint64_t height, const cryptonote::block& block, uint64_t &n_rct)
{
  write_tx(height, block.miner_tx, true, n_rct);
  for (const auto &hash: block.tx_hashes)
  {
    cryptonote::blobdata bd;
    if (!m_blockchain_storage->get_db().get_tx_blob(hash, bd))
    {
      MFATAL("failed to get block " << hash);
      return false;
    }
    cryptonote::transaction tx;
    if (!parse_and_validate_tx_from_blob(bd, tx))
    {
      MFATAL("failed to parse block " << hash);
      return false;
    }
    write_tx(height, tx, false, n_rct);
  }
  return true;
}

bool IndexdatFile::close()
{
  if (m_raw_data_file->fail())
    return false;

  m_raw_data_file->flush();
  delete m_raw_data_file;
  return true;
}


bool IndexdatFile::store_blockchain_raw(Blockchain* _blockchain_storage, tx_memory_pool* _tx_pool, boost::filesystem::path& output_file, uint64_t requested_block_stop)
{
  uint64_t num_blocks_written = 0;
  m_blockchain_storage = _blockchain_storage;
  uint64_t progress_interval = 100;
  cryptonote::block b;

  uint64_t block_stop = 0;
  uint64_t n_rct = 0;
  MINFO("source blockchain height: " <<  m_blockchain_storage->get_current_blockchain_height()-1);
  if ((requested_block_stop > 0) && (requested_block_stop < m_blockchain_storage->get_current_blockchain_height()))
  {
    MINFO("Using requested block height: " << requested_block_stop);
    block_stop = requested_block_stop;
  }
  else
  {
    block_stop = m_blockchain_storage->get_current_blockchain_height() - 1;
    MINFO("Using block height of source blockchain: " << block_stop);
  }
  MINFO("Storing index data...");
  if (!IndexdatFile::open_writer(output_file, block_stop))
  {
    MFATAL("failed to open raw file for write");
    return false;
  }
  for (m_cur_height = 1220500; m_cur_height <= block_stop; ++m_cur_height)
  {
    // this method's height refers to 0-based height (genesis block = height 0)
    crypto::hash hash = m_blockchain_storage->get_block_id_by_height(m_cur_height);
    cryptonote::blobdata bd = m_blockchain_storage->get_db().get_block_blob(hash);
    cryptonote::block block;
    if (!parse_and_validate_block_from_blob(bd, block))
    {
      MFATAL("failed to parse block " << hash);
      return false;
    }
    if (!write_block(m_cur_height, block, n_rct))
    {
      MFATAL("failed to write block " << hash);
      return false;
    }
    if (m_cur_height % NUM_BLOCKS_PER_CHUNK == 0) {
      num_blocks_written += NUM_BLOCKS_PER_CHUNK;
    }
    if (m_cur_height % progress_interval == 0) {
      std::cout << refresh_string;
      std::cout << "block " << m_cur_height << "/" << block_stop << std::flush;
    }
  }
  // print message for last block, which may not have been printed yet due to progress_interval
  std::cout << refresh_string;
  std::cout << "block " << m_cur_height-1 << "/" << block_stop << ENDL;

  MINFO("Number of blocks exported: " << num_blocks_written);

  return IndexdatFile::close();
}

