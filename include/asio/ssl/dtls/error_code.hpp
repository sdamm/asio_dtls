#ifndef ERROR_CODE_HPP
#define ERROR_CODE_HPP

#ifdef ASIO_DTLS_USE_BOOST
#include <boost/system/error_code.hpp>
namespace boost {

namespace asio {
using error_code = boost::system::error_code;
} // namespace asio
} // namespace boost
#endif // ASIO_DTLS_USE_BOOST

#endif // ERROR_CODE_HPP
