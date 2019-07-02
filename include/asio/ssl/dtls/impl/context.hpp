//
// ssl/dtls/impl/context.hpp
// ~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2005 Voipster / Indrek dot Juhani at voipster dot com
// Copyright (c) 2005-2016 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_IMPL_CONTEXT_HPP
#define ASIO_SSL_IMPL_CONTEXT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include "asio/ssl/dtls/error_code.hpp"
#include "asio/ssl/dtls/detail/macro_helper.hpp"
#include <boost/asio/detail/config.hpp>

#include <boost/asio/detail/throw_error.hpp>

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/detail/throw_error.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

template <typename VerifyCallback>
void context::set_verify_callback(VerifyCallback callback)
{
  asio::error_code ec;
  this->set_verify_callback(callback, ec);
  asio::detail::throw_error(ec, "set_verify_callback");
}

template <typename VerifyCallback>
ASIO_DTLS_SYNC_OP_VOID context::set_verify_callback(
    VerifyCallback callback, asio::error_code& ec)
{
  do_set_verify_callback(
      new asio::ssl::detail::verify_callback<VerifyCallback>(callback), ec);
  ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
}

template <typename PasswordCallback>
void context::set_password_callback(PasswordCallback callback)
{
  asio::error_code ec;
  this->set_password_callback(callback, ec);
  asio::detail::throw_error(ec, "set_password_callback");
}

template <typename PasswordCallback>
ASIO_DTLS_SYNC_OP_VOID context::set_password_callback(
    PasswordCallback callback, asio::error_code& ec)
{
  do_set_password_callback(
      new asio::ssl::detail::password_callback<PasswordCallback>(callback), ec);
  ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
}

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

#endif // ASIO_SSL_IMPL_CONTEXT_HPP
