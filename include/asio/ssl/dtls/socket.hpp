//
// ssl/dtls/dtls_socket.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DTLS_DTLS_SOCKET_HPP
#define ASIO_SSL_DTLS_DTLS_SOCKET_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "asio/ssl/dtls/detail/macro_helper.hpp"

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/config.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/detail/buffer_sequence_adapter.hpp>
#include <boost/asio/detail/handler_type_requirements.hpp>
#include <boost/asio/detail/non_const_lvalue.hpp>
#include <boost/asio/detail/noncopyable.hpp>
#include <boost/asio/detail/type_traits.hpp>
#include <boost/asio/ssl/context.hpp>
#include "asio/ssl/dtls/detail/listen_op.hpp"
#include "asio/ssl/dtls/detail/buffered_dtls_listen_op.hpp"
#include "asio/ssl/dtls/detail/buffered_handshake_op.hpp"
#include "asio/ssl/dtls/detail/handshake_op.hpp"
#include "asio/ssl/dtls/detail/datagram_io.hpp"
#include "asio/ssl/dtls/detail/read_op.hpp"
#include "asio/ssl/dtls/detail/shutdown_op.hpp"
#include "asio/ssl/dtls/detail/core.hpp"
#include "asio/ssl/dtls/detail/engine.hpp"
#include "asio/ssl/dtls/detail/write_op.hpp"
#include <boost/asio/ssl/stream_base.hpp>
#include "asio/ssl/dtls/context.hpp"
#include "asio/ssl/dtls/detail/datagram_helper.hpp"
#include <boost/asio/detail/type_traits.hpp>
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/async_result.hpp"
#include "asio/detail/buffer_sequence_adapter.hpp"
#include "asio/detail/handler_type_requirements.hpp"
#include "asio/detail/non_const_lvalue.hpp"
#include "asio/detail/noncopyable.hpp"
#include "asio/detail/type_traits.hpp"
#include "asio/ssl/context.hpp"
#include "asio/ssl/dtls/detail/listen_op.hpp"
#include "asio/ssl/dtls/detail/buffered_dtls_listen_op.hpp"
#include "asio/ssl/dtls/detail/buffered_handshake_op.hpp"
#include "asio/ssl/dtls/detail/handshake_op.hpp"
#include "asio/ssl/dtls/detail/datagram_io.hpp"
#include "asio/ssl/dtls/detail/read_op.hpp"
#include "asio/ssl/dtls/detail/shutdown_op.hpp"
#include "asio/ssl/dtls/detail/core.hpp"
#include "asio/ssl/dtls/detail/engine.hpp"
#include "asio/ssl/dtls/detail/write_op.hpp"
#include "asio/ssl/stream_base.hpp"
#include "asio/ssl/dtls/context.hpp"
#include "asio/ssl/dtls/detail/datagram_helper.hpp"
#include "asio/detail/type_traits.hpp"
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl  {
namespace dtls {
/// Provides Datagram-oriented functionality using SSL.
/**
 * The dtls class template provides asynchronous and blocking stream-oriented
 * functionality using SSL.
 *
 * @par Thread Safety
 * @e Distinct @e objects: Safe.@n
 * @e Shared @e objects: Unsafe. The application must also ensure that all
 * asynchronous operations are performed within the same implicit or explicit
 * strand.
 *
 * @par Example
 * To use the SSL dtls template with an ip::udp::socket, you would write:
 * @code
 * asio::io_context my_context;
 * asio::ssl::context ctx(asio::ssl::context::dtlsv12);
 * asio::ssl::stream<asio:ip::udp::socket> sock(my_context, ctx);
 * @endcode
 */
template <typename datagram_socket>
class socket :
  public stream_base,
  private noncopyable
{
public:
  /// The native handle type of the SSL stream.
  typedef SSL* native_handle_type;

  /// The type of the next layer.
  typedef typename remove_reference<datagram_socket>::type next_layer_type;

  /// The type of the lowest layer.
  typedef typename next_layer_type::lowest_layer_type lowest_layer_type;

  /// The type of the executor associated with the object.
  typedef typename lowest_layer_type::executor_type executor_type;

#if defined(ASIO_DTLS_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
  /// Construct a stream.
  /**
   * This constructor creates a SSL object and initialises the underlying
   * transport object.
   *
   * @param arg The argument to be passed to initialise the underlying
   * transport.
   *
   * @param ctx The SSL context to be used for the stream.
   */
  template <typename Arg>
  socket(Arg&& arg, context& ctx)
    : next_layer_(ASIO_DTLS_MOVE_CAST(Arg)(arg)),
      core_(ctx.native_handle(),
          next_layer_.lowest_layer().get_executor())
  {
    // set mtu to safe value to prevent dtls-fragmentation of the handshake
    set_mtu(1500);
    core_.engine_.set_dtls_tmp_data(&remote_endpoint_tmp_);
  }
#else // defined(ASIO_DTLS_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)
  template <typename Arg>
  socket(Arg& arg, context& ctx)
    : next_layer_(arg),
      core_(ctx.native_handle(),
          next_layer_.lowest_layer().get_executor())
  {
    // set mtu to safe value to prevent dtls-fragmentation of the handshake
    set_mtu(1500);
    core_.engine_.set_dtls_tmp_data(&remote_endpoint_tmp_);
  }
#endif // defined(ASIO_DTLS_HAS_MOVE) || defined(GENERATING_DOCUMENTATION)

  /// Destructor.
  /**
   * @note A @c dtls object must not be destroyed while there are pending
   * asynchronous operations associated with it.
   */
  ~socket()
  {
  }

  /// Get the executor associated with the object.
  /**
   * This function may be used to obtain the executor object that the stream
   * uses to dispatch handlers for asynchronous operations.
   *
   * @return A copy of the executor that stream will use to dispatch handlers.
   */
  executor_type get_executor() ASIO_DTLS_NOEXCEPT
  {
    return next_layer_.lowest_layer().get_executor();
  }

  /// Get the underlying implementation in the native type.
  /**
   * This function may be used to obtain the underlying implementation of the
   * context. This is intended to allow access to context functionality that is
   * not otherwise provided.
   *
   * @par Example
   * The native_handle() function returns a pointer of type @c SSL* that is
   * suitable for passing to functions such as @c SSL_get_verify_result and
   * @c SSL_get_peer_certificate:
   * @code
   * asio::ssl::stream<asio:ip::tcp::socket> sock(my_context, ctx);
   *
   * // ... establish connection and perform handshake ...
   *
   * if (X509* cert = SSL_get_peer_certificate(sock.native_handle()))
   * {
   *   if (SSL_get_verify_result(sock.native_handle()) == X509_V_OK)
   *   {
   *     // ...
   *   }
   * }
   * @endcode
   */
  native_handle_type native_handle()
  {
    return core_.engine_.native_handle();
  }

  /// Get a reference to the next layer.
  /**
   * This function returns a reference to the next layer in a stack of stream
   * layers.
   *
   * @return A reference to the next layer in the stack of stream layers.
   * Ownership is not transferred to the caller.
   */
  const next_layer_type& next_layer() const
  {
    return next_layer_;
  }

  /// Get a reference to the next layer.
  /**
   * This function returns a reference to the next layer in a stack of stream
   * layers.
   *
   * @return A reference to the next layer in the stack of stream layers.
   * Ownership is not transferred to the caller.
   */
  next_layer_type& next_layer()
  {
    return next_layer_;
  }

  /// Get a reference to the lowest layer.
  /**
   * This function returns a reference to the lowest layer in a stack of
   * stream layers.
   *
   * @return A reference to the lowest layer in the stack of stream layers.
   * Ownership is not transferred to the caller.
   */
  lowest_layer_type& lowest_layer()
  {
    return next_layer_.lowest_layer();
  }

  /// Get a reference to the lowest layer.
  /**
   * This function returns a reference to the lowest layer in a stack of
   * stream layers.
   *
   * @return A reference to the lowest layer in the stack of stream layers.
   * Ownership is not transferred to the caller.
   */
  const lowest_layer_type& lowest_layer() const
  {
    return next_layer_.lowest_layer();
  }

  /// Set the MTU for the DTLS handshake
  /**
   * This function sets the MTU used for the Handshake.
   *
   * @param mtu the mtu to be set
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_set_mtu
   */
  void set_mtu(int mtu, asio::error_code &ec)
  {
    if (core_.engine_.set_mtu(mtu))
    {
      ec = asio::error_code();
    }
    else
    {
      ec = asio::error_code(asio::error::invalid_argument,
                            asio::error::system_category);
    }
  }

  /// Set the MTU for the DTLS handshake
  /**
   * This function sets the MTU used for the Handshake.
   *
   * @param mtu the mtu to be set
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_set_mtu
   * Be aware that setting a small MTU will lead to fragmentation on the
   * dtls layer which conflicts with the stateless cookie exchange.
   */
  void set_mtu(int mtu)
  {
    asio::error_code ec;
    set_mtu(mtu, ec);
    asio::detail::throw_error(ec, "set_mtu");
  }

  /// Set the callback used to generate dtls cookies
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to generate a dtls cookie.
   *
   * @param callback The function object to be used for generating a cookie.
   * The function signature of the handler must be:
   * @code bool generate_callback(
   *   asio::const_buffer & // A buffer containing a cookie
   * ); @endcode
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
   */
  template <typename CookieGenerateCallback>
  ASIO_DTLS_DECL void set_cookie_generate_callback(CookieGenerateCallback cb)
  {
    asio::error_code ec;
    set_cookie_generate_callback(cb, ec);

    asio::detail::throw_error(ec, "set_cookie_generate_callback");
  }  

  ASIO_DTLS_DECL asio::error_code set_cookie_generate_callback(
      detail::cookie_generate_callback_base& cb, asio::error_code& ec)
  {
    core_.engine_.set_cookie_generate_callback(cb.clone(), ec);

    return ec;
  }

  /// Set the callback used to generate dtls cookies
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to generate a dtls cookie.
   *
   * @param callback The function object to be used for generating a cookie.
   * The function signature of the handler must be:
   * @code bool generate_callback(
   *   asio::const_buffer &cookie // Out parameter A buffer containing a cookie
   * ); @endcode
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
   */
  template <typename CookieVerifyCallback>
  ASIO_DTLS_DECL asio::error_code set_cookie_generate_callback(
      CookieVerifyCallback callback, asio::error_code &ec)
  {
    core_.engine_.set_cookie_generate_callback(
        new detail::cookie_generate_callback<
          endpoint_type, CookieVerifyCallback>(callback),
        ec
      );

    return ec;
  }

  ASIO_DTLS_DECL asio::error_code set_cookie_verify_callback(
      detail::cookie_verify_callback_base& callback, asio::error_code& ec)
  {
    core_.engine_.set_cookie_verify_callback(callback.clone(), ec);

    return ec;
  }

  /// Set the callback used to verify dtls cookies
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to verify a dtls cookie.
   *
   * @param callback The function object to be used for generating a cookie.
   * The function signature of the handler must be:
   * @code bool generate_callback(
   *   asio::const_buffer & // A buffer containing a cookie
   * ); @endcode
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
   */
  template <typename CookieCallback>
  ASIO_DTLS_DECL void set_cookie_verify_callback(CookieCallback callback)
  {
    asio::error_code ec;
    set_cookie_verify_callback(callback, ec);

    asio::detail::throw_error(ec, "set_cookie_verify_callback");
  }

  /// Set the callback used to verify dtls cookies
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to verify a dtls cookie.
   *
   * @param callback The function object to be used for generating a cookie.
   * The function signature of the handler must be:
   * @code bool generate_callback(
   *   asio::const_buffer & // A buffer containing a cookie
   * ); @endcode
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_CTX_set_cookie_generate_cb.
   */
  template <typename CookieCallback>
  ASIO_DTLS_DECL asio::error_code set_cookie_verify_callback(
      CookieCallback callback, asio::error_code &ec)
  {
    core_.engine_.set_cookie_verify_callback(
          new detail::cookie_verify_callback<endpoint_type, CookieCallback>(callback),
          ec);

    return ec;
  }

  /// Verify a DTLS cookie
  /**
   * This function verifies a received client cookie (DTLS client Hello).
   * If the cookie does is not matched by the set cookie_verify function a
   * HelloVerifyRequest is sent via the provided socket. This is a stateless
   * version of the cookie exchange done by the handshake operation.
   *
   * To prevent the server side to work as amplifier for DOS attacks
   * this function should be used to check the cookie before handshaking.
   *
   * @param socket the socket to sent the VerifyRequest with
   *
   * @param buffer data received on the listening socket
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @param ep Remote endpoint for sending a HelloVerifyRequest to
   *
   * @return true if cookie did match, false otherwise
   */
  template <typename ConstBuffer>
  bool verify_cookie(next_layer_type& socket, const ConstBuffer& buffer, asio::error_code &ec,
                     typename next_layer_type::endpoint_type ep)
  {
    remote_endpoint_tmp_ = ep;

    size_t result = ssl::dtls::detail::datagram_io(
                      dtls::detail::datagram_receive<next_layer_type>(socket),
                      dtls::detail::datagram_send_to<next_layer_type>(socket, ep),
                      core_,
                      detail::buffered_dtls_listen_op<ConstBuffer>(buffer), ec);

    return (result != 0);
  }

  /// Set the peer verification mode.
  /**
   * This function may be used to configure the peer verification mode used by
   * the stream. The new mode will override the mode inherited from the context.
   *
   * @param v A bitmask of peer verification modes. See @ref verify_mode for
   * available values.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_set_verify.
   */
  void set_verify_mode(verify_mode v)
  {
    asio::error_code ec;
    set_verify_mode(v, ec);
    asio::detail::throw_error(ec, "set_verify_mode");
  }

  /// Set the peer verification mode.
  /**
   * This function may be used to configure the peer verification mode used by
   * the stream. The new mode will override the mode inherited from the context.
   *
   * @param v A bitmask of peer verification modes. See @ref verify_mode for
   * available values.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_set_verify.
   */
  ASIO_DTLS_SYNC_OP_VOID set_verify_mode(
      verify_mode v, asio::error_code& ec)
  {
    core_.engine_.set_verify_mode(v, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Set the peer verification depth.
  /**
   * This function may be used to configure the maximum verification depth
   * allowed by the stream.
   *
   * @param depth Maximum depth for the certificate chain verification that
   * shall be allowed.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_set_verify_depth.
   */
  void set_verify_depth(int depth)
  {
    asio::error_code ec;
    set_verify_depth(depth, ec);
    asio::detail::throw_error(ec, "set_verify_depth");
  }

  /// Set the peer verification depth.
  /**
   * This function may be used to configure the maximum verification depth
   * allowed by the stream.
   *
   * @param depth Maximum depth for the certificate chain verification that
   * shall be allowed.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_set_verify_depth.
   */
  ASIO_DTLS_SYNC_OP_VOID set_verify_depth(
      int depth, asio::error_code& ec)
  {
    core_.engine_.set_verify_depth(depth, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Set the callback used to verify peer certificates.
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to verify a peer certificate.
   *
   * @param callback The function object to be used for verifying a certificate.
   * The function signature of the handler must be:
   * @code bool verify_callback(
   *   bool preverified, // True if the certificate passed pre-verification.
   *   verify_context& ctx // The peer certificate and other context.
   * ); @endcode
   * The return value of the callback is true if the certificate has passed
   * verification, false otherwise.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note Calls @c SSL_set_verify.
   */
  template <typename VerifyCallback>
  void set_verify_callback(VerifyCallback callback)
  {
    asio::error_code ec;
    this->set_verify_callback(callback, ec);
    asio::detail::throw_error(ec, "set_verify_callback");
  }

  /// Set the callback used to verify peer certificates.
  /**
   * This function is used to specify a callback function that will be called
   * by the implementation when it needs to verify a peer certificate.
   *
   * @param callback The function object to be used for verifying a certificate.
   * The function signature of the handler must be:
   * @code bool verify_callback(
   *   bool preverified, // True if the certificate passed pre-verification.
   *   verify_context& ctx // The peer certificate and other context.
   * ); @endcode
   * The return value of the callback is true if the certificate has passed
   * verification, false otherwise.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note Calls @c SSL_set_verify.
   */
  template <typename VerifyCallback>
  ASIO_DTLS_SYNC_OP_VOID set_verify_callback(VerifyCallback callback,
      asio::error_code& ec)
  {
    core_.engine_.set_verify_callback(
        new ssl::detail::verify_callback<VerifyCallback>(callback), ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Perform SSL handshaking.
  /**
   * This function is used to perform SSL handshaking on the stream. The
   * function call will block until handshaking is complete or an error occurs.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @throws asio::system_error Thrown on failure.
   */
  void handshake(handshake_type type)
  {
    asio::error_code ec;
    handshake(type, ec);
    asio::detail::throw_error(ec, "handshake");
  }

  /// Perform SSL handshaking.
  /**
   * This function is used to perform SSL handshaking on the stream. The
   * function call will block until handshaking is complete or an error occurs.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  ASIO_DTLS_SYNC_OP_VOID handshake(handshake_type type,
      asio::error_code& ec)
  {
    remote_endpoint_tmp_ = next_layer().remote_endpoint();

    ssl::dtls::detail::datagram_io(
          dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
          dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
          core_,
          ssl::dtls::detail::handshake_op(type),
          ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Perform SSL handshaking.
  /**
   * This function is used to perform SSL handshaking on the stream. The
   * function call will block until handshaking is complete or an error occurs.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @param buffers The buffered data to be reused for the handshake.
   *
   * @throws asio::system_error Thrown on failure.
   */
  template <typename ConstBufferSequence>
  void handshake(handshake_type type, const ConstBufferSequence& buffers)
  {
    asio::error_code ec;
    handshake(type, buffers, ec);
    asio::detail::throw_error(ec, "handshake");
  }

  /// Perform SSL handshaking.
  /**
   * This function is used to perform SSL handshaking on the stream. The
   * function call will block until handshaking is complete or an error occurs.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @param buffers The buffered data to be reused for the handshake.
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  template <typename ConstBufferSequence>
  ASIO_DTLS_SYNC_OP_VOID handshake(handshake_type type,
      const ConstBufferSequence& buffers, asio::error_code& ec)
  {
    remote_endpoint_tmp_ = next_layer().remote_endpoint();
    ssl::dtls::detail::datagram_io(
      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
      core_,
      detail::buffered_handshake_op<ConstBufferSequence>(type, buffers),
      ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Start an asynchronous SSL handshake.
  /**
   * This function is used to asynchronously perform an SSL handshake on the
   * stream. This function call always returns immediately.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @param handler The handler to be called when the handshake operation
   * completes. Copies will be made of the handler as required. The equivalent
   * function signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error // Result of operation.
   * ); @endcode
   */
  template <typename HandshakeHandler>
  ASIO_DTLS_INITFN_RESULT_TYPE(HandshakeHandler,
      void (asio::error_code))
  async_handshake(handshake_type type,
      ASIO_DTLS_MOVE_ARG(HandshakeHandler) handler)
  {
      return async_initiate<HandshakeHandler,
        void (asio::error_code)>(
          initiate_async_handshake(), handler, this, type);
  }

  /// Start an asynchronous SSL handshake.
  /**
   * This function is used to asynchronously perform an SSL handshake on the
   * stream. This function call always returns immediately.
   *
   * @param type The type of handshaking to be performed, i.e. as a client or as
   * a server.
   *
   * @param buffers The buffered data to be reused for the handshake. Although
   * the buffers object may be copied as necessary, ownership of the underlying
   * buffers is retained by the caller, which must guarantee that they remain
   * valid until the handler is called.
   *
   * @param handler The handler to be called when the handshake operation
   * completes. Copies will be made of the handler as required. The equivalent
   * function signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error, // Result of operation.
   *   std::size_t bytes_transferred // Amount of buffers used in handshake.
   * ); @endcode
   */
  template <typename ConstBufferSequence, typename BufferedHandshakeHandler>
  ASIO_DTLS_INITFN_RESULT_TYPE(BufferedHandshakeHandler,
      void (asio::error_code, std::size_t))
  async_handshake(handshake_type type, const ConstBufferSequence& buffers,
      ASIO_DTLS_MOVE_ARG(BufferedHandshakeHandler) handler)
  {
      return async_initiate<BufferedHandshakeHandler,
        void (asio::error_code, std::size_t)>(
          initiate_async_buffered_handshake(), handler, this, type, buffers);
  }

  /// Shut down SSL on the stream.
  /**
   * This function is used to shut down SSL on the stream. The function call
   * will block until SSL has been shut down or an error occurs.
   *
   * @throws asio::system_error Thrown on failure.
   */
  void shutdown()
  {
    asio::error_code ec;
    shutdown(ec);
    asio::detail::throw_error(ec, "shutdown");
  }

  /// Shut down SSL on the stream.
  /**
   * This function is used to shut down SSL on the stream. The function call
   * will block until SSL has been shut down or an error occurs.
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  ASIO_DTLS_SYNC_OP_VOID shutdown(asio::error_code& ec)
  {
    ssl::dtls::detail::datagram_io(
      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
      core_, detail::shutdown_op(),
      ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Asynchronously shut down SSL on the stream.
  /**
   * This function is used to asynchronously shut down SSL on the stream. This
   * function call always returns immediately.
   *
   * @param handler The handler to be called when the handshake operation
   * completes. Copies will be made of the handler as required. The equivalent
   * function signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error // Result of operation.
   * ); @endcode
   */
  template <typename ShutdownHandler>
  ASIO_DTLS_INITFN_RESULT_TYPE(ShutdownHandler,
      void (asio::error_code))
  async_shutdown(ASIO_DTLS_MOVE_ARG(ShutdownHandler) handler)
  {
      return async_initiate<ShutdownHandler,
        void (asio::error_code)>(
          initiate_async_shutdown(), handler, this);
  }

  /// Send data on the dtls connection.
  /**
   * This function is used to send data on the dtls connection. The function
   * call will block until the data has been sent successfully
   * or an error occurs.
   *
   * @param buffers The data to be written to the dtls connection.
   *
   * @returns The number of bytes written. Returns 0 if an error occurred.
   *
   * @throws asio::system_error Thrown on failure.
   */
  template <typename ConstBufferSequence>
  size_t send(ConstBufferSequence cb)
  {
    asio::error_code ec;
    std::size_t res = ssl::dtls::detail::datagram_io(
         dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
         dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
         this->core_,
         detail::write_op<ConstBufferSequence>(cb),
         ec);
    asio::detail::throw_error(ec, "send");
    return res;
  }

  /// Send data on the dtls connection.
  /**
   * This function is used to send data on the dtls connection. The function
   * call will block until the data has been sent successfully
   * or an error occurs.
   *
   * @param buffers The data to be written to the dtls connection.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @returns The number of bytes written. Returns 0 if an error occurred.
   *
   */
  template <typename ConstBufferSequence>
  std::size_t send(ConstBufferSequence cb, asio::error_code &ec)
  {
    return ssl::dtls::detail::datagram_io(
      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
      this->core_,
      detail::write_op<ConstBufferSequence>(cb),
      ec);
  }

  /// Start an asynchronous write.
  /**
   * This function is used to asynchronously write one or more bytes of data to
   * the stream. The function call always returns immediately.
   *
   * @param buffers The data to be written to the stream. Although the buffers
   * object may be copied as necessary, ownership of the underlying buffers is
   * retained by the caller, which must guarantee that they remain valid until
   * the handler is called.
   *
   * @param handler The handler to be called when the write operation completes.
   * Copies will be made of the handler as required. The equivalent function
   * signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error, // Result of operation.
   *   std::size_t bytes_transferred           // Number of bytes written.
   * ); @endcode
   *
   * @note The async_write_some operation may not transmit all of the data to
   * the peer. Consider using the @ref async_write function if you need to
   * ensure that all data is written before the blocking operation completes.
   */
  template <typename ConstBufferSequence, typename WriteHandler>
  ASIO_DTLS_INITFN_RESULT_TYPE(WriteHandler,
      void (asio::error_code, std::size_t))
  async_send(const ConstBufferSequence& buffers,
             ASIO_DTLS_MOVE_ARG(WriteHandler) handler)
  {
      return async_initiate<WriteHandler,
        void (asio::error_code, std::size_t)>(
          initiate_async_send(), handler, this, buffers);
  }

  /// Receive some data from the socket.
  /**
   * This function is used to receive data on the dtls socket.
   * The function call will block until data has been received
   * successfully or an error occurs. 
   *
   * @param buffers The buffers into which the data will be read.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @returns The number of bytes read. Returns 0 if an error occurred.
   */
  template <typename BufferSequence>
  std::size_t receive(BufferSequence mb)
  {
    asio::error_code ec;
    std::size_t res = ssl::dtls::detail::datagram_io(
      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
      this->core_,
      detail::read_op<BufferSequence>(mb),
      ec);

    asio::detail::throw_error(ec, "receive");
    return res;
  }

  /// Receive some data on a dtls connection.
  /**
   * This function is used to receive data on the dtls connection.
   * The function call will block until data has been received successfully
   * or an error occurs.
   *
   * @param buffers One or more buffers into which the data will be received.
   *
   * @returns The number of bytes received.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @par Example
   * To receive into a single data buffer use the @ref buffer function as
   * follows:
   * @code socket.receive(asio::buffer(data, size)); @endcode
   * See the @ref buffer documentation for information on receiving into
   * multiple buffers in one go, and how to use it with arrays, boost::array or
   * std::vector.
   */
  template <typename BufferSequence>
  std::size_t receive(BufferSequence mb, asio::error_code &ec)
  {
    return ssl::dtls::detail::datagram_io(
      dtls::detail::datagram_receive<next_layer_type>(this->next_layer_),
      dtls::detail::datagram_send<next_layer_type>(this->next_layer_, 0),
      this->core_,
      detail::read_op<BufferSequence>(mb),
      ec);
  }

  /// Start an asynchronous receive.
  /**
   * This function is used to asynchronously receive data on
   * the dtls socket. The function call always returns immediately.
   *
   * @param buffers The buffers into which the data will be read. Although the
   * buffers object may be copied as necessary, ownership of the underlying
   * buffers is retained by the caller, which must guarantee that they remain
   * valid until the handler is called.
   *
   * @param handler The handler to be called when the read operation completes.
   * Copies will be made of the handler as required. The equivalent function
   * signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error, // Result of operation.
   *   std::size_t bytes_transferred           // Number of bytes read.
   * ); @endcode
   */
  template <typename MutableBufferSequence, typename ReadHandler>
  ASIO_DTLS_INITFN_RESULT_TYPE(ReadHandler,
      void (asio::error_code, std::size_t))
  async_receive(const MutableBufferSequence& buffers,
      ASIO_DTLS_MOVE_ARG(ReadHandler) handler)
  {
    return async_initiate<ReadHandler,
      void (asio::error_code, std::size_t)>(
        initiate_async_receive(), handler, this, buffers);
  }
  struct initiate_async_handshake
  {
    template <typename HandshakeHandler>
    void operator()(ASIO_DTLS_MOVE_ARG(HandshakeHandler) handler,
        socket* self, handshake_type type) const
    {
      // If you get an error on the following line it means that your handler
      // does not meet the documented type requirements for a HandshakeHandler.
      ASIO_DTLS_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

      asio::detail::non_const_lvalue<HandshakeHandler> handler2(handler);
      ssl::dtls::detail::async_datagram_io(
                  dtls::detail::async_datagram_receive_timeout<next_layer_type>(self->next_layer_),
                  dtls::detail::async_datagram_send<next_layer_type>(self->next_layer_, 0),
                  self->core_,
                  dtls::detail::handshake_op(type),
                  handler2.value
                  );
    }
  };

  struct initiate_async_buffered_handshake
  {
    template <typename BufferedHandshakeHandler, typename ConstBufferSequence>
    void operator()(ASIO_DTLS_MOVE_ARG(BufferedHandshakeHandler) handler,
        socket* self, handshake_type type,
        const ConstBufferSequence& buffers) const
    {
      // If you get an error on the following line it means that your
      // handler does not meet the documented type requirements for a
      // BufferedHandshakeHandler.
      ASIO_DTLS_BUFFERED_HANDSHAKE_HANDLER_CHECK(
          BufferedHandshakeHandler, handler) type_check;

      asio::detail::non_const_lvalue<
          BufferedHandshakeHandler> handler2(handler);
      ssl::dtls::detail::async_datagram_io(
        dtls::detail::async_datagram_receive_timeout<next_layer_type>(self->next_layer_),
        dtls::detail::async_datagram_send<next_layer_type>(self->next_layer_, 0),
        self->core_,
        dtls::detail::buffered_handshake_op<ConstBufferSequence>(type, buffers),
        handler2.value);
    }
  };

  struct initiate_async_shutdown
  {
    template <typename ShutdownHandler>
    void operator()(ASIO_DTLS_MOVE_ARG(ShutdownHandler) handler,
        socket* self) const
    {
      // If you get an error on the following line it means that your handler
      // does not meet the documented type requirements for a ShutdownHandler.
      ASIO_DTLS_HANDSHAKE_HANDLER_CHECK(ShutdownHandler, handler) type_check;

      asio::detail::non_const_lvalue<ShutdownHandler> handler2(handler);
      ssl::dtls::detail::async_datagram_io(
        dtls::detail::async_datagram_receive_timeout<next_layer_type>(self->next_layer_),
        dtls::detail::async_datagram_send<next_layer_type>(self->next_layer_),
        self->core_,
        detail::shutdown_op(), handler2.value);
    }
  };

  struct initiate_async_send
  {
    template <typename WriteHandler, typename ConstBufferSequence>
    void operator()(ASIO_DTLS_MOVE_ARG(WriteHandler) handler,
        socket* self, const ConstBufferSequence& buffers) const
    {
      // If you get an error on the following line it means that your handler
      // does not meet the documented type requirements for a WriteHandler.
      ASIO_DTLS_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

      asio::detail::non_const_lvalue<WriteHandler> handler2(handler);
      dtls::detail::async_datagram_io(
          dtls::detail::async_datagram_receive<next_layer_type>(self->next_layer_),
          dtls::detail::async_datagram_send<next_layer_type>(self->next_layer_),
          self->core_,
          detail::write_op<ConstBufferSequence>(buffers), handler2.value);
    }
  };

  struct initiate_async_receive
  {
    template <typename ReadHandler, typename MutableBufferSequence>
    void operator()(ASIO_DTLS_MOVE_ARG(ReadHandler) handler,
        socket* self, const MutableBufferSequence& buffers) const
    {
      // If you get an error on the following line it means that your handler
      // does not meet the documented type requirements for a ReadHandler.
      ASIO_DTLS_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

      asio::detail::non_const_lvalue<ReadHandler> handler2(handler);
      dtls::detail::async_datagram_io(
          dtls::detail::async_datagram_receive<next_layer_type>(self->next_layer_),
          dtls::detail::async_datagram_send<next_layer_type>(self->next_layer_),
          self->core_,
          detail::read_op<MutableBufferSequence>(buffers), handler2.value);
    }
  };

  typedef typename asio::remove_reference<
    datagram_socket>::type::endpoint_type endpoint_type;

  datagram_socket next_layer_;
  ssl::dtls::detail::core core_;
  endpoint_type remote_endpoint_tmp_;
};

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

#endif // ASIO_SSL_DTLS_DTLS_SOCKET_HPP
