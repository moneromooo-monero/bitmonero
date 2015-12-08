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

#include "daemon/daemon.h"

#include "common/util.h"
#include "daemon/core.h"
#include "daemon/p2p.h"
#include "daemon/protocol.h"
#include "daemon/command_server.h"
#include "misc_log_ex.h"
#include "version.h"
#include "../../contrib/epee/include/syncobj.h"
#include "daemon_ipc_handlers.h"
#include "rpc/core_rpc_server.h"

using namespace epee;

#include <boost/program_options.hpp>
#include <functional>
#include <memory>

unsigned int epee::g_test_dbg_lock_sleep = 0;

namespace daemonize {

struct t_internals {
private:
  t_protocol protocol;
public:
  t_core core;
  t_p2p p2p;
  bool testnet_mode;
  bool restricted_rpc;

  t_internals(
      boost::program_options::variables_map const & vm
    )
    : core{vm}
    , protocol{vm, core}
    , p2p{vm, protocol}
  {
    // Handle circular dependencies
    protocol.set_p2p_endpoint(p2p.get());
    core.set_protocol(protocol.get());
    testnet_mode = command_line::get_arg(vm, command_line::arg_testnet_on);
    restricted_rpc = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc);
  }
};

void t_daemon::init_options(boost::program_options::options_description & option_spec)
{
  t_core::init_options(option_spec);
  t_p2p::init_options(option_spec);
}

t_daemon::t_daemon(
    boost::program_options::variables_map const & vm
  )
  : mp_internals{new t_internals{vm}}
{}

t_daemon::~t_daemon() = default;

// MSVC is brain-dead and can't default this...
t_daemon::t_daemon(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    other.mp_internals.reset(nullptr);
  }
}

// or this
t_daemon & t_daemon::operator=(t_daemon && other)
{
  if (this != &other)
  {
    mp_internals = std::move(other.mp_internals);
    other.mp_internals.reset(nullptr);
  }
  return *this;
}

bool t_daemon::run(bool interactive)
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't run stopped daemon"};
  }
  tools::signal_handler::install(std::bind(&daemonize::t_daemon::stop, this));

  try
  {
    daemonize::t_command_server* rpc_commands = NULL;

    mp_internals->core.run();

    if (interactive)
    {
      IPC::Daemon::init(mp_internals->core.get(), mp_internals->p2p.get(), mp_internals->testnet_mode, mp_internals->restricted_rpc);
      rpc_commands = new daemonize::t_command_server();
      rpc_commands->start_handling(std::bind(&daemonize::t_daemon::stop_p2p, this));
    }

    mp_internals->p2p.run(); // blocks until p2p goes down

    if (interactive)
    {
      rpc_commands->stop_handling();
      delete rpc_commands;
      rpc_commands = NULL;
      IPC::Daemon::stop();
    }

    LOG_PRINT("Node stopped.", LOG_LEVEL_0);
    return true;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Uncaught exception! " << ex.what());
    return false;
  }
  catch (...)
  {
    LOG_ERROR("Uncaught exception!");
    return false;
  }
}

void t_daemon::stop()
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't stop stopped daemon"};
  }
  mp_internals->p2p.stop();
  mp_internals.reset(nullptr); // Ensure resources are cleaned up before we return
  IPC::Daemon::stop();
}

void t_daemon::stop_p2p()
{
  if (nullptr == mp_internals)
  {
    throw std::runtime_error{"Can't send stop signal to a stopped daemon"};
  }
  mp_internals->p2p.get().send_stop_signal();
}

} // namespace daemonize
