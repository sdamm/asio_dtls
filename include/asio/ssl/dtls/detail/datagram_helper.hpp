#ifndef ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H
#define ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/asio/detail/config.hpp>

#include "asio/ssl/dtls/error_code.hpp"
#include <boost/asio/steady_timer.hpp>

#include <boost/asio/detail/push_options.hpp>
#else  // ASIO_DTLS_USE_BOOST
#include "asio/detail/config.hpp"

#include "asio/error_code.hpp"
#include "asio/steady_timer.hpp"

#include "asio/ssl/dtls/detail/macro_helper.hpp"

#include "asio/detail/push_options.hpp"
#endif // ASIO_DTLS_USE_BOOST
#include <functional>

#ifdef ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

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
  void operator()(const Buffer& buffer, ASIO_DTLS_MOVE_ARG(CallBack) cb) const
  {
    socket_.async_receive(buffer, message_flags(), ASIO_DTLS_MOVE_CAST(CallBack)(cb));
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
    , timer_(new asio::steady_timer(socket.get_executor()))
    , timeout_(new asio::steady_timer::duration(chrono::seconds(1)))
    , timedout_(new bool(false))
  {
    timer_->expires_after(asio::steady_timer::duration::max());
  }

  async_datagram_receive_timeout(const async_datagram_receive_timeout& other)
      : socket_(other.socket_)
      , timer_(other.timer_)
      , timeout_(other.timeout_)
      , timedout_(other.timedout_)
  {
  }

  template <typename Buffer, typename CallBack>
  void operator()(const Buffer& buffer, CallBack cb)
  {
    asio::detail::shared_ptr<asio::steady_timer> timer(timer_);

    std::function<void(asio::error_code, std::size_t)> tmp(cb);

    asio::detail::shared_ptr<bool> timedout(timedout_);
    socket_.async_receive(buffer, message_flags(),
      [tmp, timer, timedout](asio::error_code ec, std::size_t size)
      {
        timer->cancel();
        if(*timedout)
        {
          asio::error_code ec(asio::error::timed_out, asio::error::system_category);
          tmp(ec, size);
        }
        else
        {
          tmp(ec, size);
        }
      });

    SocketType &socket = socket_;
    timer_->expires_after(*timeout_);
    timer_->async_wait([&socket, timedout](const asio::error_code &ec)
    {
        if(!ec)
        {
            *timedout = true;
            socket.close();
        }
    });
  }

  ~async_datagram_receive_timeout()
  {
  }

private:
  SocketType& socket_;
  asio::detail::shared_ptr<asio::steady_timer> timer_;
  asio::detail::shared_ptr<asio::steady_timer::duration > timeout_;
  asio::detail::shared_ptr<bool> timedout_;
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
  void operator()(const Buffer& buffer, ASIO_DTLS_MOVE_ARG(CallBack) cb) const
  {
    socket_.async_send(buffer, flags_, ASIO_DTLS_MOVE_CAST(CallBack)(cb));
  }

private:
  SocketType& socket_;
  message_flags flags_;
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

#endif // ASIO_SSL_DTLS_DETAIL_DATAGRAM_HELPER_H
