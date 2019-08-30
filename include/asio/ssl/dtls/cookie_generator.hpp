#ifndef ASIO_SSL_DTLS_COOKIE_GENERATOR_HPP
#define ASIO_SSL_DTLS_COOKIE_GENERATOR_HPP

#include <string>

#if ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

template <typename secretgenerator, const char* HashFunction, typename EndpointType>
bool cookie_generator(std::string &cookie,
     const EndpointType& ep);

} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#if defined(ASIO_HEADER_ONLY)
# include "asio/ssl/dtls/impl/cookie_generator.ipp"
#endif // defined(ASIO_HEADER_ONLY)

#endif // ASIO_SSL_DTLS_COOKIE_GENERATOR_HPP
