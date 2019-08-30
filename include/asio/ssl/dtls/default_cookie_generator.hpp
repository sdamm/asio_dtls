#ifndef ASIO_SSL_DTLS_DEFAULT_COOKIE_GENERATOR_HPP
#define ASIO_SSL_DTLS_DEFAULT_COOKIE_GENERATOR_HPP

#include "cookie_generator.hpp"
#include "secret_generator.hpp"

#if ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

using default_secret_generator = secret_generator<256/8, 600>;

template <typename EndpointType>
auto default_cookie_generator = cookie_generator<default_secret_generator, "BLAKE2s256", EndpointType>;

} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_SSL_DTLS_DEFAULT_COOKIE_GENERATOR_HPP
