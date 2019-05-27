#!/usr/bin/env python3

# Copyright (c) 2018 The Monero Project
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import time
import os

"""Test daemon mining RPC calls

Test the following RPCs:
    - start_mining
    - stop_mining
    - mining_status
"""

from framework.daemon import Daemon
from framework.wallet import Wallet

class MiningTest():
    def run_test(self):
        self.reset()
        self.create()
        self.mine()
        self.test_randomx()

    def reset(self):
        print 'Resetting blockchain'
        daemon = Daemon()
        daemon.pop_blocks(1000)
        daemon.flush_txpool()

    def create(self):
        print 'Creating wallet'
        wallet = Wallet()
        # close the wallet if any, will throw if none is loaded
        try: wallet.close_wallet()
        except: pass
        res = wallet.restore_deterministic_wallet(seed = 'velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted')

    def mine(self):
        print "Test mining"

        daemon = Daemon()
        wallet = Wallet()

        # check info/height/balance before generating blocks
        res_info = daemon.get_info()
        prev_height = res_info.height
        res_getbalance = wallet.get_balance()
        prev_balance = res_getbalance.balance

        res_status = daemon.mining_status()

        res = daemon.start_mining('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', threads_count = 1)

        res_status = daemon.mining_status()
        assert res_status.active == True
        assert res_status.threads_count == 1
        assert res_status.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert res_status.is_background_mining_enabled == False
        assert res_status.block_reward >= 600000000000

        # wait till we mined a few of them
        timeout = 60 # randomx init can be slow...
        timeout_height = prev_height
        while True:
            time.sleep(1)
            res_info = daemon.get_info()
            height = res_info.height
            if height >= prev_height + 5:
                break
            if height > timeout_height:
              timeout = 5
              timeout_height = height
            else:
              timeout -= 1
            assert timeout >= 0

        res = daemon.stop_mining()
        res_status = daemon.mining_status()
        assert res_status.active == False

        res_info = daemon.get_info()
        new_height = res_info.height

        wallet.refresh()
        res_getbalance = wallet.get_balance()
        balance = res_getbalance.balance
        assert balance >= prev_balance + (new_height - prev_height) * 600000000000

        res = daemon.start_mining('42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm', threads_count = 1, do_background_mining = True)
        res_status = daemon.mining_status()
        assert res_status.active == True
        assert res_status.threads_count == 1
        assert res_status.address == '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'
        assert res_status.is_background_mining_enabled == True
        assert res_status.block_reward >= 600000000000

        # don't wait, might be a while if the machine is busy, which it probably is
        res = daemon.stop_mining()
        res_status = daemon.mining_status()
        assert res_status.active == False

    def test_randomx(self):
        print "Test RandomX"

        daemon = Daemon()
        wallet = Wallet()

        daemon.pop_blocks(1000)

        epoch = int(os.environ['SEEDHASH_EPOCH_BLOCKS'])
        lag = int(os.environ['SEEDHASH_EPOCH_LAG'])
        address = '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'

        # check we can generate blocks, and that the seed hash changes when expected
        res = daemon.getblocktemplate(address)
        first_seed_hash = res.seed_hash
        daemon.generateblocks(address, 1 + lag)
        res = daemon.mining_status()
        assert res.active == False
        assert res.pow_algorithm == 'RandomX'
        res = daemon.getblocktemplate(address)
        seed_hash = res.seed_hash
        t0 = time.time()
        daemon.generateblocks(address, epoch - 3)
        t0 = time.time() - t0
        res = daemon.get_info()
        assert res.height == lag + epoch - 1
        res = daemon.getblocktemplate(address)
        assert seed_hash == res.seed_hash
        t0 = time.time() - t0
        daemon.generateblocks(address, 1)
        t0 = time.time() - t0
        res = daemon.get_info()
        assert res.height == lag + epoch
        daemon.generateblocks(address, 1)
        res = daemon.getblocktemplate(address)
        assert seed_hash != res.seed_hash
        new_seed_hash = res.seed_hash
        t0 = time.time() - t0
        daemon.generateblocks(address, epoch - 1)
        t0 = time.time() - t0
        res = daemon.getblocktemplate(address)
        assert new_seed_hash == res.seed_hash
        daemon.generateblocks(address, 1)
        res = daemon.getblocktemplate(address)
        assert new_seed_hash != res.seed_hash
        new_seed_hash = res.seed_hash
        t0 = time.time() - t0
        daemon.generateblocks(address, epoch - 1)
        t0 = time.time() - t0
        res = daemon.getblocktemplate(address)
        assert new_seed_hash == res.seed_hash
        daemon.generateblocks(address, 1)
        res = daemon.getblocktemplate(address)
        assert new_seed_hash != res.seed_hash
        print 'First mining: ' + str(t0)

        # pop all these blocks, and feed them again to monerod
        print 'Recreating the chain'
        res = daemon.get_info()
        height = res.height
        assert height == lag + epoch * 3 + 1
        block_hashes = [x.hash for x in daemon.getblockheadersrange(0, height - 1).headers]
        assert len(block_hashes) == height
        blocks = []
        for i in range(len(block_hashes)):
            res = daemon.getblock(i)
            assert res.block_header.hash == block_hashes[i]
            blocks.append(res.blob)
        daemon.pop_blocks(height)
        res = daemon.get_info()
        assert res.height == 1
        res = daemon.getblocktemplate(address)
        assert first_seed_hash == res.seed_hash
        t0 = time.time()
        for h in range(len(block_hashes)):
            res = daemon.submitblock(blocks[h])
        t0 = time.time() - t0
        res = daemon.get_info()
        assert height == res.height
        res = daemon.getblocktemplate(address)
        assert new_seed_hash != res.seed_hash
        res = daemon.pop_blocks(1)
        res = daemon.getblocktemplate(address)
        assert new_seed_hash == res.seed_hash
        print 'Submit: ' + str(t0)

        # start mining from the genesis block again
        print 'Mining from genesis block again'
        res = daemon.get_height()
        top_hash = res.hash
        res = daemon.getblockheaderbyheight(0)
        genesis_block_hash = res.block_header.hash
        t0 = time.time()
        daemon.generateblocks(address, height - 2, prev_block = genesis_block_hash)
        t0 = time.time() - t0
        res = daemon.get_info()
        assert res.height == height - 1
        assert res.top_block_hash == top_hash
        print 'Second mining: ' + str(t0)

        # that one will cause a huge reorg
        print 'Adding one to reorg'
        res = daemon.generateblocks(address, 1)
        assert len(res.blocks) == 1
        new_top_hash = res.blocks[0]
        res = daemon.get_info()
        assert res.height == height
        assert res.top_block_hash == new_top_hash


if __name__ == '__main__':
    MiningTest().run_test()
