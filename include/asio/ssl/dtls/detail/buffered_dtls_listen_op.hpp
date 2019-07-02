//
// ssl/dtls/detail/buffered_dtls_listen_op.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2016 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DTLS_DETAIL_BUFFERED_LISTEN_OP_HPP
#define ASIO_SSL_DTLS_DETAIL_BUFFERED_LISTEN_OP_HPP

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

template <typename ConstBuffer>
class buffered_dtls_listen_op
{
public:
  buffered_dtls_listen_op(const ConstBuffer& buffers)
    : buffer_(buffers)
  {
  }

  ssl::dtls::detail::engine::want operator()(dtls::detail::engine& eng,
      asio::error_code& ec,
      std::size_t& bytes_transferred) const
  {
    eng.put_input(buffer_);
    bytes_transferred = asio::buffer_size(buffer_);
    ssl::dtls::detail::engine::want result = eng.dtls_listen(ec);

    // Don't retry -> call again to retry
    if(result == ssl::dtls::detail::engine::want_output_and_retry)
    {
      result = ssl::dtls::detail::engine::want_output;
    }

    if(result == ssl::dtls::detail::engine::want_output)
    {
      // This is not what we transfered, but allows to indicate a wrong cookie
      bytes_transferred = 0;
    }

    return result;
  }

  template <typename Handler>
  void call_handler(Handler& handler,
      const asio::error_code& ec,
      const std::size_t& bytes_transferred) const
  {
    handler(ec, bytes_transferred);
  }

private:
  ConstBuffer buffer_;
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

#endif // ASIO_SSL_DTLS_DETAIL_BUFFERED_LISTEN_OP_HPP
