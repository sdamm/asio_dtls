//
// ssl/dtls/detail/ssl_app_data.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
//

#ifndef ASIO_SSL_DETAIL_SSL_APP_DATA_HPP
#define ASIO_SSL_DETAIL_SSL_APP_DATA_HPP

#include "asio/ssl/detail/verify_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_generate_callback.hpp"
#include "asio/ssl/dtls/detail/cookie_verify_callback.hpp"

namespace asio {
namespace ssl {
namespace dtls {
namespace detail {

class ssl_app_data
{
public:
   ssl_app_data()
     : verify_certificate_callback(0)
     , cookie_generate_callback(0)
     , cookie_verify_callback(0)
     , dtls_tmp(0)
   {
   }

   ~ssl_app_data()
   {
     if(verify_certificate_callback)
     {
       delete verify_certificate_callback;
       verify_certificate_callback = 0;
     }

     if(cookie_generate_callback)
     {
       delete cookie_generate_callback;
       cookie_generate_callback = 0;
     }

     if (cookie_verify_callback)
     {
       delete cookie_verify_callback;
       cookie_verify_callback = 0;
     }
   }

   void setVerifyCallback(ssl::detail::verify_callback_base* cb)
   {
     if(verify_certificate_callback)
     {
       delete verify_certificate_callback;
     }

     verify_certificate_callback = cb;
   }

   void setCookieGenerateCallback(dtls::detail::cookie_generate_callback_base* cb)
   {
     if (cookie_generate_callback)
     {
       delete cookie_generate_callback;
     }

     cookie_generate_callback = cb;
   }

   void setCookieVerifyCallback(dtls::detail::cookie_verify_callback_base* cb)
   {
     if(cookie_verify_callback)
     {
       delete cookie_verify_callback;
     }

     cookie_verify_callback = cb;
   }

   ssl::detail::verify_callback_base *getVerifyCallback()
   {
     return verify_certificate_callback;
   }

   dtls::detail::cookie_generate_callback_base *getCookieGenerateCallback()
   {
     return cookie_generate_callback;
   }

   dtls::detail::cookie_verify_callback_base *getCookieVerifyCallback()
   {
     return cookie_verify_callback;
   }

   void set_dtls_tmp(void* data)
   {
     dtls_tmp = data;
   }

   void *getDTLSTmp()
   {
     return dtls_tmp;
   }

private:
   ssl::detail::verify_callback_base* verify_certificate_callback;
   dtls::detail::cookie_generate_callback_base* cookie_generate_callback;
   dtls::detail::cookie_verify_callback_base* cookie_verify_callback;
   void *dtls_tmp;
};

} // namespace detail
} // namespace dtls
} // namespace ssl
} // namespace asio

#endif // ASIO_SSL_DTLS_DETAIL_SSL_APP_DATA_HPP
