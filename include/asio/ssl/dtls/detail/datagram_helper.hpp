#ifndef ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H
#define ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "asio/detail/config.hpp"

#include "asio/error_code.hpp"
#include "asio/steady_timer.hpp"

#include "asio/detail/push_options.hpp"
#include <functional>
namespace asio{
namespace ssl{
namespace dtls {
namespace detail {

template <typename SocketType>
class datagram_send_to
{
public:
  typedef typename SocketType::message_flags message_flags;

  datagram_send_to(SocketType &socket,
                   typename SocketType::endpoint_type ep,
                   message_flags flags = message_flags())
    : socket_(socket)
    , endpoint_(ep)
    , flags_(flags)
  {

  }

  template <typename Buffer>
  size_t operator()(const Buffer& buffer, asio::error_code& ec) const
  {
    return socket_.send_to(buffer, endpoint_, flags_, ec);
  }

private:
  SocketType& socket_;
  typename SocketType::endpoint_type endpoint_;
  typename SocketType::message_flags flags_;
};

template <typename SocketType>
class datagram_send
{
public:
  typedef typename SocketType::message_flags message_flags;

  datagram_send(SocketType &socket, message_flags flags = message_flags())
    : socket_(socket)
    , flags_(flags)
  {

  }

  template <typename Buffer>
  size_t operator()(const Buffer& buffer, asio::error_code& ec) const
  {
    return socket_.send(buffer, flags_, ec);
  }

private:
  SocketType& socket_;
  message_flags flags_;
};

template <typename SocketType>
class datagram_receive
{
public:
  typedef typename SocketType::message_flags message_flags;

  datagram_receive(SocketType &socket)
    : socket_(socket)
  {

  }

  template <typename Buffer>
  size_t operator()(const Buffer& buffer, asio::error_code& ec) const
  {
    return socket_.receive(buffer, message_flags(), ec);
  }

private:
  SocketType& socket_;
};

template <typename SocketType>
class async_datagram_receive
{
public:
  typedef typename SocketType::message_flags message_flags;

  async_datagram_receive(SocketType& socket)
    : socket_(socket)
  {

  }

  template <typename Buffer, typename CallBack>
  void operator()(const Buffer& buffer, ASIO_MOVE_ARG(CallBack) cb) const
  {
    socket_.async_receive(buffer, message_flags(), ASIO_MOVE_CAST(CallBack)(cb));
  }

private:
  SocketType& socket_;
};

template <typename SocketType>
class async_datagram_receive_timeout
{
public:
  typedef typename SocketType::message_flags message_flags;

  async_datagram_receive_timeout(SocketType& socket)
    : socket_(socket)
    , timer_(socket.get_io_context())
    , timeout_(new asio::steady_timer::duration(chrono::seconds(1)))
  {
    timer_.expires_after(asio::steady_timer::duration::max());
  }

  async_datagram_receive_timeout(const async_datagram_receive_timeout& other)
      : socket_(other.socket_)
      , timer_(socket_.get_io_context())
      , timeout_(other.timeout_)
  {
      timer_.expires_after(asio::steady_timer::duration::max());
  }

  template <typename Buffer, typename CallBack>
  void operator()(const Buffer& buffer, ASIO_MOVE_ARG(CallBack) cb)
  {
    socket_.async_receive(buffer, message_flags(),
                          ASIO_MOVE_CAST(CallBack)(cb));

    SocketType &socket = socket_;
    timer_.async_wait([&socket](const asio::error_code &ec)
    {
        if(!ec)
        {
            socket.close();
        }
    });

    timer_.expires_after(*timeout_);
  }

private:
  SocketType& socket_;
  asio::steady_timer timer_;
  asio::detail::shared_ptr<asio::steady_timer::duration > timeout_;
};

template <typename SocketType>
class async_datagram_send
{
public:
  typedef typename SocketType::message_flags message_flags;

  async_datagram_send(SocketType& socket, message_flags flags = message_flags())
    : socket_(socket)
    , flags_(flags)
  {

  }

  template <typename Buffer, typename CallBack>
  void operator()(const Buffer& buffer, ASIO_MOVE_ARG(CallBack) cb) const
  {
    socket_.async_send(buffer, flags_, ASIO_MOVE_CAST(CallBack)(cb));
  }

private:
  SocketType& socket_;
  message_flags flags_;
};




} // namespace detail
} // namespace dtls
} // namespace ssl
} // namespace asio

#include "asio/detail/pop_options.hpp"

#endif // ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H
