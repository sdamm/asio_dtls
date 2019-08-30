#ifndef ASIO_SSL_DTLS_SECRET_GENERATOR_HPP
#define ASIO_SSL_DTLS_SECRET_GENERATOR_HPP

#include <chrono>
#include <array>
#include <cstdint>
#include <random>

#if ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

template <unsigned int secret_length, unsigned int renewaltime_seconds>
class secret_generator
{
public:
  using secret_type = std::array<std::uint8_t, secret_length>;

  const secret_type& operator()()
  {
    static std::chrono::duration<int> renewaltime{std::chrono::seconds(renewaltime_seconds)};
    static auto last_generated = std::chrono::system_clock::now();
    static auto secret = std::move(generate_secret());

    if(std::chrono::system_clock::now() - last_generated > renewaltime)
    {
      secret = std::move(generate_secret());
    }

    return secret;
  }  

private:
  static secret_type&& generate_secret()
  {
    secret_type secret;
    if(RAND_pseudo_bytes(secret.data(), secret.size()) != 1)
    {
      std::default_random_engine generator(time(0));
      std::uniform_int_distribution<uint8_t> distribution(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());
      for(auto &e : secret)
      {
        e = distribution(generator);
      }
    }
    return secret;
  }
};

} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_SSL_DTLS_SECRET_GENERATOR_HPP
