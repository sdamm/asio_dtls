#ifndef DEFAULT_COOKIE_GENERATOR_HPP
#define DEFAULT_COOKIE_GENERATOR_HPP

#include <openssl/evp.h>

#if ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) 

template <typename EndpointType>
bool siphash_cookie_generator(std::string &cookie,
     const EndpointType& ep)
{
  ;
}

#endif // (OPENSSL_VERSION_NUMBER >= 0x10100000L)

} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#if defined(ASIO_HEADER_ONLY)
# include "asio/ssl/dtls/impl/siphash_cookie_generator.ipp"
#endif // defined(ASIO_HEADER_ONLY)

#endif // DEFAULT_COOKIE_GENERATOR_HPP
