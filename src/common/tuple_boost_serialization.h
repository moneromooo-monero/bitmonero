// Copyright (c) 2019, The Monero Project
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

#include <tuple>

namespace boost
{
  namespace serialization
  {
    template <class Archive, class T0, class T1, class T2>
    inline void serialize(Archive &a, std::tuple<T0, T1, T2> &x, const boost::serialization::version_type ver)
    {
      a & std::get<0>(x);
      a & std::get<1>(x);
      a & std::get<2>(x);
    }
    template <class Archive, class T0, class T1, class T2, class T3>
    inline void serialize(Archive &a, std::tuple<T0, T1, T2, T3> &x, const boost::serialization::version_type ver)
    {
      a & std::get<0>(x);
      a & std::get<1>(x);
      a & std::get<2>(x);
      a & std::get<3>(x);
    }
    template <class Archive, class T0, class T1, class T2, class T3, class T4>
    inline void serialize(Archive &a, std::tuple<T0, T1, T2, T3, T4> &x, const boost::serialization::version_type ver)
    {
      a & std::get<0>(x);
      a & std::get<1>(x);
      a & std::get<2>(x);
      a & std::get<3>(x);
      a & std::get<4>(x);
    }
    template <class Archive, class T0, class T1, class T2, class T3, class T4, class T5>
    inline void serialize(Archive &a, std::tuple<T0, T1, T2, T3, T4, T5> &x, const boost::serialization::version_type ver)
    {
      a & std::get<0>(x);
      a & std::get<1>(x);
      a & std::get<2>(x);
      a & std::get<3>(x);
      a & std::get<4>(x);
      a & std::get<5>(x);
    }
  }
}
