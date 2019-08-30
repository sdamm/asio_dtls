#ifndef ASIO_SSL_DTLS_IMPL_COOKIE_GENERATOR_HPP
#define ASIO_SSL_DTLS_IMPL_COOKIE_GENERATOR_HPP

#include <memory>
#include <openssl/evp.h>

#if ASIO_DTLS_USE_BOOST
namespace boost {
#endif // ASIO_DTLS_USE_BOOST

namespace asio {
namespace ssl {
namespace dtls {

template <typename secretgenerator, const char* HashFunction, typename EndpointType>
bool cookie_generator(std::string &cookie,
     const EndpointType& ep)
{
  static const EVP_MD *md = EVP_get_digestbyname(HashFunction);
  if(md == nullptr) return false;

  static std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX *)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if(!mdctx) return false;

  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  if(EVP_MD_CTX_reset(mdctx.get()) != 1) return false;
  if(EVP_DigestInit_ex(mdctx.get(), md, NULL) != 1) return false;
  if(EVP_DigestUpdate(mdctx.get(), ep.data(), ep.size()) != 1) return false;
  if(EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len) != 1) return false;

  cookie = std::string(reinterpret_cast<char*>(md_value), md_len);
}

} // namespace dtls
} // namespace ssl
} // namespace asio

#if ASIO_DTLS_USE_BOOST
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_SSL_DTLS_IMPL_COOKIE_GENERATOR_HPP
