#ifndef ASIO_DTLS_ACCEPTOR_HPP
#define ASIO_DTLS_ACCEPTOR_HPP

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/push_options.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/basic_socket.hpp>
#include <boost/asio/basic_io_object.hpp>
#include "asio/ssl/dtls/socket.hpp"
#include <boost/asio/detail/memory.hpp>
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"
#include <boost/asio/ssl/error.hpp>
#include <boost/system/error_code.hpp>
#include "asio/ssl/dtls/context.hpp"
#include <boost/asio/executor_work_guard.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/push_options.hpp"

#include "asio/io_context.hpp"
#include "asio/basic_socket.hpp"
#include "asio/basic_io_object.hpp"
#include "asio/ssl/dtls/socket.hpp"
#include "asio/detail/memory.hpp"
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"
#include "asio/ssl/error.hpp"
#include "asio/error_code.hpp"
#include "asio/ssl/dtls/context.hpp"
#include "asio/executor_work_guard.hpp"
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

template <typename DatagramSocketType, typename Executor = executor>
class acceptor;

template <typename DatagramSocketType, typename Executor>
class acceptor
{
public:
  typedef asio::ssl::dtls::socket<DatagramSocketType> dtls_sock;

  typedef typename DatagramSocketType::endpoint_type endpoint_type;
  typedef typename DatagramSocketType::protocol_type protocol_type;

  /// The type of the executor associated with the object.
  typedef Executor executor_type;

  /// Construct an acceptor without opening it.
  /**
   * This constructor creates an acceptor without opening it to listen for new
   * connections. The open() function must be called before the acceptor can
   * accept new socket connections.
   *
   * @param context An execution context which provides the I/O executor that
   * the acceptor will use, by default, to dispatch handlers for any
   * asynchronous operations performed on the acceptor.
   */
  template <typename ExecutionContext>
  explicit acceptor(ExecutionContext& context, endpoint_type &ep,
      typename enable_if<
        is_convertible<ExecutionContext&, execution_context&>::value
      >::type* = 0)
        : sock_(context)
        , remoteEndPoint_()
        , cookie_generate_callback_(nullptr)
        , cookie_verify_callback_(nullptr)
  {
	  sock_.open(ep.protocol());
  }

  explicit acceptor(const executor_type &ex, endpoint_type &ep)
    : sock_(ex)
    , remoteEndPoint_()
    , cookie_generate_callback_(nullptr)
    , cookie_verify_callback_(nullptr)
  {
    sock_.open(ep.protocol());
  }

  /// Open the acceptor using the specified protocol.
  /**
   * This function opens the socket acceptor so that it will use the specified
   * protocol.
   *
   * @param protocol An object specifying which protocol is to be used.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(executor);
   * acceptor.open(asio::ip::tcp::v4());
   * @endcode
   */
  void open(const protocol_type& protocol = protocol_type())
  {
    asio::error_code ec;
    sock_.open(protocol, ec);
    asio::detail::throw_error(ec, "open");
  }

  /// Open the acceptor using the specified protocol.
  /**
   * This function opens the socket acceptor so that it will use the specified
   * protocol.
   *
   * @param protocol An object specifying which protocol is to be used.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(executor);
   * asio::error_code ec;
   * acceptor.open(asio::ip::tcp::v4(), ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  ASIO_DTLS_SYNC_OP_VOID open(const protocol_type& protocol,
                         asio::error_code& ec)
  {
    sock_.open(protocol, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Bind the acceptor to the given local endpoint.
  /**
   * This function binds the socket acceptor to the specified endpoint on the
   * local machine.
   *
   * @param endpoint An endpoint on the local machine to which the socket
   * acceptor will be bound.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), 12345);
   * acceptor.open(endpoint.protocol());
   * acceptor.bind(endpoint);
   * @endcode
   */
  void bind(const endpoint_type& endpoint)
  {
    asio::error_code ec;
    sock_.bind(endpoint, ec);
    asio::detail::throw_error(ec, "bind");
  }

  /// Bind the acceptor to the given local endpoint.
  /**
   * This function binds the socket acceptor to the specified endpoint on the
   * local machine.
   *
   * @param endpoint An endpoint on the local machine to which the socket
   * acceptor will be bound.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), 12345);
   * acceptor.open(endpoint.protocol());
   * asio::error_code ec;
   * acceptor.bind(endpoint, ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  ASIO_DTLS_SYNC_OP_VOID bind(const endpoint_type& endpoint,
                         asio::error_code& ec)
  {
    sock_.bind(endpoint, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Close the acceptor.
  /**
   * This function is used to close the acceptor. Any asynchronous accept
   * operations will be cancelled immediately.
   *
   * A subsequent call to open() is required before the acceptor can again be
   * used to again perform socket accept operations.
   *
   * @throws asio::system_error Thrown on failure.
   */
  void close()
  {
    asio::error_code ec;
    sock_.close(ec);
    asio::detail::throw_error(ec, "close");
  }

  /// Close the acceptor.
  /**
   * This function is used to close the acceptor. Any asynchronous accept
   * operations will be cancelled immediately.
   *
   * A subsequent call to open() is required before the acceptor can again be
   * used to again perform socket accept operations.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::error_code ec;
   * acceptor.close(ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  ASIO_DTLS_SYNC_OP_VOID close(asio::error_code& ec)
  {
    sock_.close(ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Cancel all asynchronous operations associated with the acceptor.
  /**
   * This function causes all outstanding asynchronous connect, send and receive
   * operations to finish immediately, and the handlers for cancelled operations
   * will be passed the asio::error::operation_aborted error.
   *
   * @throws asio::system_error Thrown on failure.
   */
  void cancel()
  {
    asio::error_code ec;
    sock_.cancel(ec);
    asio::detail::throw_error(ec, "cancel");
  }

  /// Cancel all asynchronous operations associated with the acceptor.
  /**
   * This function causes all outstanding asynchronous connect, send and receive
   * operations to finish immediately, and the handlers for cancelled operations
   * will be passed the asio::error::operation_aborted error.
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  ASIO_DTLS_SYNC_OP_VOID cancel(asio::error_code& ec)
  {
    sock_.cancel(ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Set an option on the acceptor.
  /**
   * This function is used to set an option on the acceptor.
   *
   * @param option The new option value to be set on the acceptor.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @sa SettableSocketOption @n
   * asio::socket_base::reuse_address
   * asio::socket_base::enable_connection_aborted
   *
   * @par Example
   * Setting the SOL_SOCKET/SO_REUSEADDR option:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::reuse_address option(true);
   * acceptor.set_option(option);
   * @endcode
   */
  template <typename SettableSocketOption>
  void set_option(const SettableSocketOption& option)
  {
    asio::error_code ec;
    sock_.set_option(option, ec);
    asio::detail::throw_error(ec, "set_option");
  }

  /// Set an option on the acceptor.
  /**
   * This function is used to set an option on the acceptor.
   *
   * @param option The new option value to be set on the acceptor.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @sa SettableSocketOption @n
   * asio::socket_base::reuse_address
   * asio::socket_base::enable_connection_aborted
   *
   * @par Example
   * Setting the SOL_SOCKET/SO_REUSEADDR option:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::reuse_address option(true);
   * asio::error_code ec;
   * acceptor.set_option(option, ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  template <typename SettableSocketOption>
  ASIO_DTLS_SYNC_OP_VOID set_option(const SettableSocketOption& option,
                               asio::error_code& ec)
  {
    sock_.set_option(option, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Get an option from the acceptor.
  /**
   * This function is used to get the current value of an option on the
   * acceptor.
   *
   * @param option The option value to be obtained from the acceptor.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @sa GettableSocketOption @n
   * asio::socket_base::reuse_address
   *
   * @par Example
   * Getting the value of the SOL_SOCKET/SO_REUSEADDR option:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::reuse_address option;
   * acceptor.get_option(option);
   * bool is_set = option.get();
   * @endcode
   */
  template <typename GettableSocketOption>
  void get_option(GettableSocketOption& option)
  {
    asio::error_code ec;
    sock_.get_option(option, ec);
    asio::detail::throw_error(ec, "get_option");
  }

  /// Get an option from the acceptor.
  /**
   * This function is used to get the current value of an option on the
   * acceptor.
   *
   * @param option The option value to be obtained from the acceptor.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @sa GettableSocketOption @n
   * asio::socket_base::reuse_address
   *
   * @par Example
   * Getting the value of the SOL_SOCKET/SO_REUSEADDR option:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::reuse_address option;
   * asio::error_code ec;
   * acceptor.get_option(option, ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * bool is_set = option.get();
   * @endcode
   */
  template <typename GettableSocketOption>
  ASIO_DTLS_SYNC_OP_VOID get_option(GettableSocketOption& option,
                               asio::error_code& ec)
  {
    sock_.get_option(option, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Set the Callback used to generate DTLS Cookies
  /**
   * This function object is used to specify a callback function that will be
   * called by the implementation when it needs to generate a dtls cookie.
   *
   * @par callback the callback use to generate DTLS Cookies
   * @code bool callback(
   *   std::string &cookie, // Out parameter the Cookie generated by this callback
   *   const boost::asio::ip::udp::endpoint& ep // The peer endpoint
   * ); @endcode
   * The return value of the callback is true if the cookie was
   * successfully created. If false is returned the handshake will
   * be aborted.
   * @note This will truncate the length of the Cookie to DTLS1_COOKIE_LENGTH
   * when the generated Cookie is longer.
   */
  template <typename CookieGenerateCallback>
  void set_cookie_generate_callback(CookieGenerateCallback callback)
  {
    if (cookie_generate_callback_)
    {
      delete cookie_generate_callback_;
    }

    cookie_generate_callback_ =
        new detail::cookie_generate_callback<typename DatagramSocketType::endpoint_type, CookieGenerateCallback>(callback);
  }

  /// Set the Callback used to verify DTLS Cookies
  /**
   * This function object is used to specify a callback function that will be
   * called by the implementation when it needs to verify a dtls cookie.
   *
   * @par callback the callback use to generate DTLS Cookies
   * @code bool callback(
   *   const std::string &cookie, // the Cookie to verify
   *   const boost::asio::ip::udp::endpoint& ep // The peer endpoint
   * ); @endcode
   * The return value of the callback is true if the cookie was
   * successfully verified.
   * @note The Cookie provided is truncated to DTLS1_COOKIE_LENGTH bytes.
   */
  template <typename CookieCallback>
  void set_cookie_verify_callback(CookieCallback callback)
  {
    if (cookie_verify_callback_)
    {
      delete cookie_verify_callback_;
    }

    cookie_verify_callback_ =
        new detail::cookie_verify_callback
        <typename DatagramSocketType::endpoint_type, CookieCallback>(callback);
  }

  /// Perform an IO control command on the acceptor.
  /**
   * This function is used to execute an IO control command on the acceptor.
   *
   * @param command The IO control command to be performed on the acceptor.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @sa IoControlCommand @n
   * asio::socket_base::non_blocking_io
   *
   * @par Example
   * Getting the number of bytes ready to read:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::non_blocking_io command(true);
   * socket.io_control(command);
   * @endcode
   */
  template <typename IoControlCommand>
  void io_control(IoControlCommand& command)
  {
    asio::error_code ec;
    sock_.io_control(command, ec);
    asio::detail::throw_error(ec, "io_control");
  }

  /// Perform an IO control command on the acceptor.
  /**
   * This function is used to execute an IO control command on the acceptor.
   *
   * @param command The IO control command to be performed on the acceptor.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @sa IoControlCommand @n
   * asio::socket_base::non_blocking_io
   *
   * @par Example
   * Getting the number of bytes ready to read:
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::acceptor::non_blocking_io command(true);
   * asio::error_code ec;
   * socket.io_control(command, ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  template <typename IoControlCommand>
  ASIO_DTLS_SYNC_OP_VOID io_control(IoControlCommand& command,
                               asio::error_code& ec)
  {
    sock_.io_control(command, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Gets the non-blocking mode of the acceptor.
  /**
   * @returns @c true if the acceptor's synchronous operations will fail with
   * asio::error::would_block if they are unable to perform the requested
   * operation immediately. If @c false, synchronous operations will block
   * until complete.
   *
   * @note The non-blocking mode has no effect on the behaviour of asynchronous
   * operations. Asynchronous operations will never fail with the error
   * asio::error::would_block.
   */
  bool non_blocking() const
  {
    return sock_.non_blocking();
  }

  /// Sets the non-blocking mode of the acceptor.
  /**
   * @param mode If @c true, the acceptor's synchronous operations will fail
   * with asio::error::would_block if they are unable to perform the
   * requested operation immediately. If @c false, synchronous operations will
   * block until complete.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @note The non-blocking mode has no effect on the behaviour of asynchronous
   * operations. Asynchronous operations will never fail with the error
   * asio::error::would_block.
   */
  void non_blocking(bool mode)
  {
    asio::error_code ec;
    sock_.non_blocking(mode, ec);
    asio::detail::throw_error(ec, "non_blocking");
  }

  /// Sets the non-blocking mode of the acceptor.
  /**
   * @param mode If @c true, the acceptor's synchronous operations will fail
   * with asio::error::would_block if they are unable to perform the
   * requested operation immediately. If @c false, synchronous operations will
   * block until complete.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @note The non-blocking mode has no effect on the behaviour of asynchronous
   * operations. Asynchronous operations will never fail with the error
   * asio::error::would_block.
   */
  ASIO_DTLS_SYNC_OP_VOID non_blocking(
      bool mode, asio::error_code& ec)
  {
    sock_.non_blocking(mode, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Gets the non-blocking mode of the native acceptor implementation.
  /**
   * This function is used to retrieve the non-blocking mode of the underlying
   * native acceptor. This mode has no effect on the behaviour of the acceptor
   * object's synchronous operations.
   *
   * @returns @c true if the underlying acceptor is in non-blocking mode and
   * direct system calls may fail with asio::error::would_block (or the
   * equivalent system error).
   *
   * @note The current non-blocking mode is cached by the acceptor object.
   * Consequently, the return value may be incorrect if the non-blocking mode
   * was set directly on the native acceptor.
   */
  bool native_non_blocking() const
  {
    return sock_.native_non_blocking();
  }

  /// Sets the non-blocking mode of the native acceptor implementation.
  /**
   * This function is used to modify the non-blocking mode of the underlying
   * native acceptor. It has no effect on the behaviour of the acceptor object's
   * synchronous operations.
   *
   * @param mode If @c true, the underlying acceptor is put into non-blocking
   * mode and direct system calls may fail with asio::error::would_block
   * (or the equivalent system error).
   *
   * @throws asio::system_error Thrown on failure. If the @c mode is
   * @c false, but the current value of @c non_blocking() is @c true, this
   * function fails with asio::error::invalid_argument, as the
   * combination does not make sense.
   */
  void native_non_blocking(bool mode)
  {
    asio::error_code ec;
    sock_.native_non_blocking(mode, ec);
    asio::detail::throw_error(ec, "native_non_blocking");
  }

  /// Sets the non-blocking mode of the native acceptor implementation.
  /**
   * This function is used to modify the non-blocking mode of the underlying
   * native acceptor. It has no effect on the behaviour of the acceptor object's
   * synchronous operations.
   *
   * @param mode If @c true, the underlying acceptor is put into non-blocking
   * mode and direct system calls may fail with asio::error::would_block
   * (or the equivalent system error).
   *
   * @param ec Set to indicate what error occurred, if any. If the @c mode is
   * @c false, but the current value of @c non_blocking() is @c true, this
   * function fails with asio::error::invalid_argument, as the
   * combination does not make sense.
   */
  ASIO_DTLS_SYNC_OP_VOID native_non_blocking(
      bool mode, asio::error_code& ec)
  {
    sock_.native_non_blocking(mode, ec);
    ASIO_DTLS_SYNC_OP_VOID_RETURN(ec);
  }

  /// Get the local endpoint of the acceptor.
  /**
   * This function is used to obtain the locally bound endpoint of the acceptor.
   *
   * @returns An object that represents the local endpoint of the acceptor.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::endpoint endpoint = acceptor.local_endpoint();
   * @endcode
   */
  endpoint_type local_endpoint() const
  {
    return sock_.local_endpoint();
  }

  /// Get the local endpoint of the acceptor.
  /**
   * This function is used to obtain the locally bound endpoint of the acceptor.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @returns An object that represents the local endpoint of the acceptor.
   * Returns a default-constructed endpoint object if an error occurred and the
   * error handler did not throw an exception.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::error_code ec;
   * asio::ip::tcp::endpoint endpoint = acceptor.local_endpoint(ec);
   * if (ec)
   * {
   *   // An error occurred.
   * }
   * @endcode
   */
  endpoint_type local_endpoint(asio::error_code& ec) const
  {
    return sock_.local_endpoint(ec);
  }

  /// Accept a new connection.
  /**
   * This function is used to accept a new connection from a peer into the
   * given socket. The function call will block until a new connection has been
   * accepted successfully or an error occurs.
   *
   * @par peer The socket into which the new connection will be accepted.
   * @par buffer Buffer for data received during cookie verification,
   * should after successfull verification be passed to the handshake function.
   *
   * @throws asio::system_error Thrown on failure.
   *
   * @par Example
   * @code
   * asio::ip::tcp::acceptor acceptor(io_context);
   * ...
   * asio::ip::tcp::socket socket(io_context);
   * acceptor.accept(socket);
   * @endcode
   */
  template<typename MutableBuffer>
  void accept(socket<DatagramSocketType>& peer,
              const MutableBuffer& buffer)
  {
    asio::error_code ec;
    endpoint_type ep;

    do
    {
        sock_.receive_from(buffer, ep);
    }
    while(!ec && peer.verify_cookie(sock_, buffer, ec, ep));

    asio::detail::throw_error(ec, "accept");
  }

  /// Start an asynchronous accept.
  /**
   * This function is used to asynchronously accept a new connection. The
   * function call always returns immediately.
   *
   * @par sock The DTLS Socket used for the Cookie verificationn.
   * @par buffer Buffer for data received during cookie verification,
   * should after successfull verification be passed to the handshake function.
   *
   * @par handler The handler to be called when the accept operation
   * completes. Copies will be made of the handler as required. The function
   * signature of the handler must be:
   * @code void handler(
   *   const asio::error_code& error, // Result of operation.
   *   typename Protocol::socket peer // On success, the newly accepted socket.
   * ); @endcode
   * Regardless of whether the asynchronous operation completes immediately or
   * not, the handler will not be invoked from within this function. Invocation
   * of the handler will be performed in a manner equivalent to using
   * asio::io_context::post().
   * @param ec Set to indicate what error occurred, if any.
   *
   * @par Example
   * @code
   * using dtls_socket = asio::ssl::dtls::socket<asio::ip::udp>;
   * void accept_handler(const asio::error_code& error,
   *     dtls_socket peer)
   * {
   *   if (!error)
   *   {
   *     // Accept succeeded.
   *     peer.handshake(buffer, ec);
   *   }
   * }
   *
   * ...
   *
   * asio::ssl::dtls::acceptor<dtls_socket> acceptor(io_context);
   * dtls_socket sock(...);
   * ...
   * acceptor.async_accept(sock, buffer, accept_handler, ec);
   * @endcode
   */
  template <typename AcceptHandler, typename MutableBuffer>
  ASIO_DTLS_INITFN_RESULT_TYPE(AcceptHandler,
                          void (asio::error_code, DatagramSocketType))
  async_accept(socket<DatagramSocketType> &sock,
               const MutableBuffer& buffer,
               ASIO_DTLS_MOVE_ARG(AcceptHandler) handler,
               asio::error_code &ec)
  {
    // If you get an error on the following line it means that your handler does
    // not meet the documented type requirements for a ReceiveHandler.
    ASIO_DTLS_READ_HANDLER_CHECK(AcceptHandler, handler) type_check;

    async_completion<AcceptHandler,
        void (asio::error_code,
              size_t)> init(handler);

    if(cookie_generate_callback_ == nullptr ||
       cookie_verify_callback_ == nullptr)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000)
      ::SSLerr(
        SSL_F_DTLSV1_LISTEN,
        SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
#endif
      ec = asio::error_code(::ERR_get_error(),
                            asio::error::get_ssl_category());
      return;
    }

    sock.set_cookie_generate_callback(*cookie_generate_callback_, ec);
    if(ec)
    {
      return;
    }

    sock.set_cookie_verify_callback(*cookie_verify_callback_, ec);
    if(ec)
    {
      return;
    }

    sock_.async_receive_from(buffer,
                            remoteEndPoint_,
    dtls_acceptor_callback_helper<
      ASIO_DTLS_HANDLER_TYPE(AcceptHandler,void(const asio::error_code&, size_t))>
        (*this, std::move(init.completion_handler), sock, buffer));

    return init.result.get();
  }

  executor_type get_executor() ASIO_DTLS_NOEXCEPT
  {
    return sock_.get_executor();
  }

private:

  template <typename AcceptHandler>
  class dtls_acceptor_callback_helper
  {
  public:
    dtls_acceptor_callback_helper(acceptor<DatagramSocketType> &acc,
                                  AcceptHandler&& ah,
                                  socket<DatagramSocketType>& sock,
                                  asio::mutable_buffer buffer)
      : acceptor_(acc)
      , ah_(std::forward<AcceptHandler>(ah))
      , sock_(sock)
      , buffer_(buffer)
      , work_(acc.sock_.get_executor())
    {
    }

    void operator ()(const asio::error_code& ec, size_t size)
    {
      if(ec)
      {
        ah_(ec, size);
      }
      else
      {
        asio::error_code ec;
        if (sock_.verify_cookie(acceptor_.sock_,
                            buffer_,
                            ec, acceptor_.remoteEndPoint_))
        {
          sock_.next_layer().open(acceptor_.sock_.local_endpoint().protocol());

          asio::socket_base::reuse_address option(true);
          sock_.next_layer().set_option(option);
          sock_.next_layer().bind(acceptor_.sock_.local_endpoint());

          sock_.next_layer().connect(acceptor_.remoteEndPoint_);

          ah_(ec, size);
        }
        else
        {
          acceptor_.sock_.async_receive_from(
             buffer_, acceptor_.remoteEndPoint_, *this);
        }
      }
    }

    executor_type& get_executor() const ASIO_DTLS_NOEXCEPT
    {
      return sock_.get_executor();
    }

  private:
    acceptor<DatagramSocketType> &acceptor_;
    AcceptHandler ah_;
    socket<DatagramSocketType> &sock_;
    asio::mutable_buffer buffer_;
    asio::executor_work_guard<
      decltype(std::declval<DatagramSocketType&>().get_executor())> work_;
  };


  DatagramSocketType sock_;
  typename DatagramSocketType::endpoint_type remoteEndPoint_;
  detail::cookie_generate_callback_base* cookie_generate_callback_;
  detail::cookie_verify_callback_base* cookie_verify_callback_;
};

} // namespace dtls
} // namespace ssl
} // namespace asio

#ifdef ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/pop_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/pop_options.hpp"
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_DTLS_ACCEPTOR_HPP
