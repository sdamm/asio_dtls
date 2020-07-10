#ifndef ASIO_SSL_DETAIL_PSK_SERVER_CALLBACK_HPP
#define ASIO_SSL_DETAIL_PSK_SERVER_CALLBACK_HPP

#include "asio/detail/config.hpp"

#include <cstddef>
#include <string>
#include "asio/ssl/context_base.hpp"

#include "asio/detail/push_options.hpp"

namespace asio {
namespace ssl {
namespace detail {

class psk_server_callback_base
{
public:
  virtual ~psk_server_callback_base()
  {
  }

  virtual bool call(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) = 0;
  virtual unsigned int result() const = 0;
  virtual psk_server_callback_base* clone() = 0;
};

template <typename PskServerCallback>
class psk_server_callback : public psk_server_callback_base
{
public:
  explicit psk_server_callback(PskServerCallback callback)
    : _callback(callback), _retval(0)
  {
  }

  virtual bool call(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
  {
    return _callback(ssl, identity, psk, max_psk_len);
  }

  virtual unsigned int result() const
  {
    return _retval;
  }

  virtual psk_server_callback_base* clone()
  {
    return new psk_server_callback<PskServerCallback>(_callback);
  }

private:
  PskServerCallback _callback;
  unsigned int      _retval;
};

} // namespace detail
} // namespace ssl
} // namespace asio


#include "asio/detail/pop_options.hpp"

#endif // ASIO_SSL_DETAIL_PSK_SERVER_CALLBACK_HPP
