//
// ssl/dtls/detail/engine.hpp
// ~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DTLS_DETAIL_ENGINE_HPP
#define ASIO_SSL_DTLS_DETAIL_ENGINE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include "macro_helper.hpp"
#include "asio/ssl/dtls/error_code.hpp"
#include <boost/asio/detail/config.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/detail/static_mutex.hpp>
#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/detail/verify_callback.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <asio/ssl/dtls/detail/cookie_generate_callback.hpp>
#include <asio/ssl/dtls/detail/cookie_verify_callback.hpp>

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/buffer.hpp"
#include "asio/detail/static_mutex.hpp"
#include "asio/ssl/detail/openssl_types.hpp"
#include "asio/ssl/detail/verify_callback.hpp"
#include "asio/ssl/stream_base.hpp"
#include "asio/ssl/verify_mode.hpp"
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {
namespace detail {

class engine
{
public:
  enum want
  {
    // Returned by functions to indicate that the engine wants input. The input
    // buffer should be updated to point to the data. The engine then needs to
    // be called again to retry the operation.
    want_input_and_retry = -2,

    // Returned by functions to indicate that the engine wants to write output.
    // The output buffer points to the data to be written. The engine then
    // needs to be called again to retry the operation.
    want_output_and_retry = -1,

    // Returned by functions to indicate that the engine doesn't need input or
    // output.
    want_nothing = 0,

    // Returned by functions to indicate that the engine wants to write output.
    // The output buffer points to the data to be written. After that the
    // operation is complete, and the engine does not need to be called again.
    want_output = 1
  };

  // Construct a new engine for the specified context.
  ASIO_DTLS_DECL explicit engine(SSL_CTX* context);

  // Destructor.
  ASIO_DTLS_DECL ~engine();

  // Get the underlying implementation in the native type.
  ASIO_DTLS_DECL SSL* native_handle();

  // Set the MTU used for handshaking
  ASIO_DTLS_DECL bool set_mtu(int mtu);

  // Set temporary data for cookie validation
  ASIO_DTLS_DECL void set_dtls_tmp_data(void* data);

  // Get temporary data for cookie validation
  ASIO_DTLS_DECL void* get_dtls_tmp_data();

  // Set Callback for cookie generation
  ASIO_DTLS_DECL asio::error_code set_cookie_generate_callback(
    dtls::detail::cookie_generate_callback_base* callback,
    asio::error_code& ec);

  // Set Callback for cookie validation
  ASIO_DTLS_DECL asio::error_code set_cookie_verify_callback(
    dtls::detail::cookie_verify_callback_base * callback,
    asio::error_code& ec);

  // Set the peer verification mode.
  ASIO_DTLS_DECL asio::error_code set_verify_mode(
      verify_mode v, asio::error_code& ec);

  // Set the peer verification depth.
  ASIO_DTLS_DECL asio::error_code set_verify_depth(
      int depth, asio::error_code& ec);

  // Set a peer certificate verification callback.
  ASIO_DTLS_DECL asio::error_code set_verify_callback(
      ssl::detail::verify_callback_base* callback, asio::error_code& ec);

  // Perform an DTLS_v1_listen to verify the dtls cookie
  ASIO_DTLS_DECL want dtls_listen(asio::error_code& ec);

  // Perform an SSL handshake using either SSL_connect (client-side) or
  // SSL_accept (server-side).
  ASIO_DTLS_DECL want handshake(
      stream_base::handshake_type type, asio::error_code& ec);

  // Perform a graceful shutdown of the SSL session.
  ASIO_DTLS_DECL want shutdown(asio::error_code& ec);

  // Write bytes to the SSL session.
  ASIO_DTLS_DECL want write(const asio::const_buffer& data,
      asio::error_code& ec, std::size_t& bytes_transferred);

  // Read bytes from the SSL session.
  ASIO_DTLS_DECL want read(const asio::mutable_buffer& data,
      asio::error_code& ec, std::size_t& bytes_transferred);

  // Get output data to be written to the transport.
  ASIO_DTLS_DECL asio::mutable_buffer get_output(
      const asio::mutable_buffer& data);

  // Put input data that was read from the transport.
  ASIO_DTLS_DECL asio::const_buffer put_input(
      const asio::const_buffer& data);

  // Map an error::eof code returned by the underlying transport according to
  // the type and state of the SSL session. Returns a const reference to the
  // error code object, suitable for passing to a completion handler.
  ASIO_DTLS_DECL const asio::error_code& map_error_code(
      asio::error_code& ec) const;

private:
  // Disallow copying and assignment.
  engine(const engine&);
  engine& operator=(const engine&);

  // Callback used when the SSL implementation wants to verify a certificate.
  ASIO_DTLS_DECL static int verify_callback_function(
      int preverified, X509_STORE_CTX* ctx);

  // Callback used when the SSL implementation wants to generate a DTLS cookie
  ASIO_DTLS_DECL static int generate_cookie_function(
      SSL *ssl, unsigned char *cookie, unsigned int *length);

  // Callback used when the SSL implementation wants to verify a DTLS cookie
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  ASIO_DTLS_DECL static int verify_cookie_function(
      SSL *ssl, const unsigned char *cookie, unsigned int length);
#else  //(OPENSSL_VERSION_NUMBER >= 0x10100000L)
  ASIO_DTLS_DECL static int verify_cookie_function(
      SSL *ssl, unsigned char *cookie, unsigned int length);
#endif //(OPENSSL_VERSION_NUMBER >= 0x10100000L)

#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
  // The SSL_accept function may not be thread safe. This mutex is used to
  // protect all calls to the SSL_accept function.
  ASIO_DTLS_DECL static asio::detail::static_mutex& accept_mutex();
#endif // (OPENSSL_VERSION_NUMBER < 0x10000000L)

  // Perform one operation. Returns >= 0 on success or error, want_read if the
  // operation needs more input, or want_write if it needs to write some output
  // before the operation can complete.
  ASIO_DTLS_DECL want perform(int (engine::* op)(void*, std::size_t),
      void* data, std::size_t length, asio::error_code& ec,
      std::size_t* bytes_transferred);

  // Adapt the DTLSv1_listen function to the signatoure needed for perform().
  ASIO_DTLS_DECL int do_dtls_listen(void*, std::size_t);

  // Adapt the SSL_accept function to the signature needed for perform().
  ASIO_DTLS_DECL int do_accept(void*, std::size_t);

  // Adapt the SSL_connect function to the signature needed for perform().
  ASIO_DTLS_DECL int do_connect(void*, std::size_t);

  // Adapt the SSL_shutdown function to the signature needed for perform().
  ASIO_DTLS_DECL int do_shutdown(void*, std::size_t);

  // Adapt the SSL_read function to the signature needed for perform().
  ASIO_DTLS_DECL int do_read(void* data, std::size_t length);

  // Adapt the SSL_write function to the signature needed for perform().
  ASIO_DTLS_DECL int do_write(void* data, std::size_t length);

  SSL* ssl_;
  BIO* ext_bio_;
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

#if defined(ASIO_HEADER_ONLY)
# include "asio/ssl/dtls/detail/impl/engine.ipp"
#endif // defined(ASIO_HEADER_ONLY)

#endif // ASIO_SSL_DTLS_DETAIL_ENGINE_HPP
