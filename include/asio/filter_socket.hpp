#ifndef ASIO_DTLS_FILTER_SOCKET_HPP
#define ASIO_DTLS_FILTER_SOCKET_HPP

#include <map>
#include <functional>
#include "asio/ip/basic_endpoint.hpp"
#include "asio/buffer.hpp"
#include "asio/socket_base.hpp"

#ifdef ASIO_DTLS_USE_BOOST
namespace boost
#endif // ASIO_DTLS_USE_BOOST

#include <memory>
#include <iostream>

namespace asio
{
namespace dtls
{

template <typename SocketType, typename Executor = any_io_executor>
class filter_subsocket;

template <typename SocketType, typename Executor = any_io_executor>
class filter_socket;

template <typename SocketType, typename Executor>
class filter_socket
{
public:
  using callback_type = std::function<void (const asio::error_code&, std::size_t)>;
  typedef typename SocketType::endpoint_type endpoint_type;
  typedef SocketType next_layer_type;


  template <typename ...Params>
  filter_socket(Params&&... params)
      : sock_(std::forward<Params>(params)...)
      , subsocks_()
      , ep_()
      , defaultsock_(ep_, {})
      , receiving(false)
  {
  }

  SocketType &next_layer()
  {
    return sock_;
  }

  template<typename MutableBufferSequence>
  void async_receive_from(endpoint_type &ep, const MutableBufferSequence & buff, callback_type &&cb)
  {
    defaultsock_ = {ep, {cb, buff}};
    if(!receiving)
    {
      receiving = true;
      receive();
    }
  }


  template<typename MutableBufferSequence>
  void async_receive(const endpoint_type &ep, const MutableBufferSequence & buff, callback_type &&cb)
  {
    auto tmp = subsocks_.find(ep);
    if(tmp != subsocks_.end())
    {
      asio::error_code ec((int)std::errc::operation_canceled, asio::system_category());
      tmp->second.callback(ec, 0);
      subsocks_.erase(tmp);
    }
    subsocks_.insert({ep, {cb, buff}});
    if(!receiving)
    {
      receiving = true;
      receive();
    }
  }

private:
  void receive()
  {
    if(subsocks_.empty() && !defaultsock_.second.callback)
    {
      receiving = false;
    }
    else
    {
      sock_.async_receive_from(asio::buffer(static_cast<char*>(nullptr), 0), ep_, asio::socket_base::message_peek,
        [this](const asio::error_code &ec, std::size_t size){
          received(ec, size);
        });
    }
  }

  void received(const asio::error_code &ec, std::size_t)
  {
    if(ec)
    {
        error(ec);
    }
    else
    {
      auto tmp = subsocks_.find(ep_);
      if(tmp != subsocks_.end())
      {
        sock_.async_receive_from(tmp->second.buffer, ep_, [this, tmp](const asio::error_code &ec, std::size_t size){
          if(ec)
          {
            error(ec);
          }
          else
          {
            auto callback = tmp->second.callback;
            subsocks_.erase(ep_);
            callback(ec, size);
            receive();
          }
        });
      }
      else if(defaultsock_.second.callback)
      {
        defaultReceive();
      }
      else
      {
        dropPacket();
      }
    }
  }

  void defaultReceive()
  {
    sock_.async_receive_from(defaultsock_.second.buffer, defaultsock_.first, [this](const asio::error_code &ec, std::size_t size){
        if(ec)
        {
          error(ec);
        }
        else
        {
          defaultsock_.second.callback(ec, size);
          receive();
        }});
  }

  void dropPacket()
  {
    sock_.async_receive_from(asio::buffer(buffer, 1), ep_, [this](const asio::error_code &ec, std::size_t){
      if(ec)
      {
        error(ec);
      }
      else
      {
        receive();
      }});
  }

  void error(const asio::error_code &ec)
  {
    for(auto &h : subsocks_)
    {
        h.second.callback(ec, 0);
    }
    subsocks_.clear();
  }

  struct helper
  {
    callback_type callback;
    asio::mutable_buffer buffer;
  };


  SocketType sock_;
  std::map<endpoint_type, helper> subsocks_;
  endpoint_type ep_;
  std::pair<std::reference_wrapper<endpoint_type>, helper> defaultsock_;
  bool receiving;
  char buffer[2];
};

template <typename SocketType, typename Executor>
class filter_subsocket
{
public:
    using parent_socket = filter_socket<SocketType, Executor>;
    using endpoint_type = typename SocketType::endpoint_type;
    using callback_type = typename parent_socket::callback_type;

    filter_subsocket(parent_socket &filtsock, endpoint_type ep)
        : parent_(filtsock)
        , bound_endpoint_(ep)
    {
    }

    template<typename MutableBufferSequence>
    void async_receive(const MutableBufferSequence & buff, callback_type &&cb)
    {
        parent_.async_receive(bound_endpoint_, buff, std::forward<callback_type>(cb));
    }


private:
    parent_socket &parent_;
    endpoint_type bound_endpoint_;
};

} // namespace dtls
} // namespace asio

#ifdef ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_FILTER_SOCKET_HPP
