#!/usr/bin/env python3

# Copyright (c) 2019 The Monero Project
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

"""Test multiuser transfers
"""

from framework.daemon import Daemon
from framework.wallet import Wallet

class MultiuserTest():
    seeds = [
        'velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted',
        'peeled mixture ionic radar utopia puddle buying illness nuns gadget river spout cavernous bounced paradise drunk looking cottage jump tequila melting went winter adjust spout',
        'dilute gutter certain antics pamphlet macro enjoy left slid guarded bogeys upload nineteen bomb jubilee enhanced irritate turnip eggs swung jukebox loudly reduce sedan slid',
    ]

    addresses = [
        '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm',
        '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW',
        '46r4nYSevkfBUMhuykdK3gQ98XDqDTYW1hNLaXNvjpsJaSbNtdXh1sKMsdVgqkaihChAzEy29zEDPMR3NHQvGoZCLGwTerK',
    ]

    def run_test(self):
        assert len(self.seeds) == len(self.addresses)
        self.create()
        self.mine()

    def create(self):
        print 'Creating wallets'
        self.wallet = [None] * len(self.seeds)
        for i in range(len(self.seeds)):
            self.wallet[i] = Wallet(idx = i)
            # close the wallet if any, will throw if none is loaded
            try: self.wallet[i].close_wallet()
            except: pass
            res = self.wallet[i].restore_deterministic_wallet(seed = self.seeds[i])
            res = self.wallet[i].get_address()
            assert res.address == self.addresses[i]

    def mine(self):
        print("Mining some blocks")
        daemon = Daemon()

        for i in range(len(self.addresses)):
            daemon.generateblocks(self.addresses[i], 5)
            for i in range(len(self.wallet)):
                self.wallet[i].refresh()
        daemon.generateblocks(self.addresses[0], 65)

    def simple_transaction(self):
        dst = {'address': '46r4nYSevkfBUMhuykdK3gQ98XDqDTYW1hNLaXNvjpsJaSbNtdXh1sKMsdVgqkaihChAzEy29zEDPMR3NHQvGoZCLGwTerK', amount: 1000000000000}
        res = self.wallet[0].transfer_multiuser([dst])
        assert len(res.multiuser_data) > 0
        multiuser_data = res.multiuser_data
        res = self.wallet[1].transfer_multiuser([dst], multiuser_data = multiuser_data)
        assert len(res.multiuser_data) > 0
        multiuser_data = res.multiuser_data
        res = self.wallet[1].sign_multiuser(multiuser_data)
        assert len(res.multiuser_data) > 0
        multiuser_data = res.multiuser_data
        res = self.wallet[0].sign_multiuser(multiuser_data)
        assert len(res.multiuser_data) > 0
        multiuser_data = res.multiuser_data
        res = self.wallet[0].submit_multiuser(multiuser_data)
        assert len(res.tx_hash) == 64
        txid = res.tx_hash

        res = daemon.get_transactions([txid])
        assert len(res.txs) == 1
        assert not 'missed_tx' in res or len(res.missed_tx) == 0
        tx = res.txs[0]
        assert tx.tx_hash == txid
        assert tx.in_pool == True
        daemon.generateblocks('46r4nYSevkfBUMhuykdK3gQ98XDqDTYW1hNLaXNvjpsJaSbNtdXh1sKMsdVgqkaihChAzEy29zEDPMR3NHQvGoZCLGwTerK', 1)
        res = daemon.get_transactions([txid])
        assert len(res.txs) == 1
        assert not 'missed_tx' in res or len(res.missed_tx) == 0
        tx = res.txs[0]
        assert tx.tx_hash == txid
        assert tx.in_pool == False

        # TODO
        self.wallet[0].refresh()
        self.wallet[1].refresh()


class Guard:
    def __enter__(self):
        for i in range(3):
            Wallet(idx = i).auto_refresh(False)
    def __exit__(self, exc_type, exc_value, traceback):
        for i in range(3):
            Wallet(idx = i).auto_refresh(True)

if __name__ == '__main__':
    with Guard() as guard:
        MultiuserTest().run_test()
