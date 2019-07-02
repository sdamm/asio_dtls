//
// ssl/dtls/detail/shutdown_op.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DTLS_DETAIL_SHUTDOWN_OP_HPP
#define ASIO_SSL_DTLS_DETAIL_SHUTDOWN_OP_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/config.hpp>

#include "asio/ssl/dtls/detail/engine.hpp"

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/ssl/dtls/detail/engine.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {
namespace detail {

class shutdown_op
{
public:
  engine::want operator()(engine& eng,
      asio::error_code& ec,
      std::size_t& bytes_transferred) const
  {
    bytes_transferred = 0;
    return eng.shutdown(ec);
  }

  template <typename Handler>
  void call_handler(Handler& handler,
      const asio::error_code& ec,
      const std::size_t&) const
  {
    if (ec == asio::error::eof)
    {
      // The engine only generates an eof when the shutdown notification has
      // been received from the peer. This indicates that the shutdown has
      // completed successfully, and thus need not be passed on to the handler.
      handler(asio::error_code());
    }
    else
    {
      handler(ec);
    }
  }
};

} // namespace detail
} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/pop_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/pop_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_SSL_DTLS_DETAIL_SHUTDOWN_OP_HPP
