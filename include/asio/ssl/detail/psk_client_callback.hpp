#ifndef ASIO_SSL_DETAIL_PSK_CLIENT_CALLBACK_HPP
#define ASIO_SSL_DETAIL_PSK_CLIENT_CALLBACK_HPP

#include "asio/detail/config.hpp"

#include <cstddef>
#include <string>
#include "asio/ssl/context_base.hpp"

#include "asio/detail/push_options.hpp"

namespace asio {
namespace ssl {
namespace detail {

class psk_client_callback_base
{
public:
  virtual ~psk_client_callback_base()
  {
  }

  virtual bool call(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) = 0;
  virtual unsigned int result() const = 0;
  virtual psk_client_callback_base* clone() = 0;
};

template <typename PskClientCallback>
class psk_client_callback : public psk_client_callback_base
{
public:
  explicit psk_client_callback(PskClientCallback callback)
    : _callback(callback), _retval(0)
  {
  }

  virtual bool call(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len)
  {
    _retval = _callback(ssl, hint, identity, max_identity_len, psk, max_psk_len);
    return true;
  }

  virtual unsigned int result() const
  {
    return _retval;
  }

  virtual psk_client_callback_base* clone()
  {
    return new psk_client_callback<PskClientCallback>(_callback);
  }

private:
  PskClientCallback _callback;
  unsigned int      _retval;
};

} // namespace detail
} // namespace ssl
} // namespace asio


#include "asio/detail/pop_options.hpp"

#endif // ASIO_SSL_DETAIL_PSK_CLIENT_CALLBACK_HPP
