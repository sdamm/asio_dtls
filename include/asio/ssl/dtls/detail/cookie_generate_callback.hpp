//
// ssl/dtls/detail/cookie_generate_callback.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2016 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DTLS_DETAIL_COOKIE_GENERATE_CALLBACK_HPP
#define ASIO_SSL_DTLS_DETAIL_COOKIE_GENERATE_CALLBACK_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/config.hpp>

#include <boost/asio/ssl/verify_context.hpp>

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/ssl/verify_context.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {
namespace detail {

class cookie_generate_callback_base
{
public:
  virtual ~cookie_generate_callback_base()
  {
  }

  virtual bool call(std::string &cookie, void *data) = 0;

  virtual cookie_generate_callback_base *clone() = 0;
};

template <typename EndpointType, typename CookieGenerateCallback>
class cookie_generate_callback : public cookie_generate_callback_base
{
public:
  explicit cookie_generate_callback(CookieGenerateCallback callback)
    : callback_(callback)
  {
  }

  virtual bool call(std::string &cookie, void *data)
  {
    EndpointType& ep = *static_cast<EndpointType*>(data);
    return callback_(cookie, ep);
  }

  virtual cookie_generate_callback_base* clone()
  {
    return new
      cookie_generate_callback<EndpointType, CookieGenerateCallback>(callback_);
  }

private:
  CookieGenerateCallback callback_;
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

#endif // ASIO_SSL_DTLS_DETAIL_COOKIE_GENERATE_CALLBACK_HPP
