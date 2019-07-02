//
// dtls.hpp
// ~~~~~~~
//
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_DTLS_HPP
#define ASIO_DTLS_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#ifdef ASIO_DTLS_USE_BOOST
#include "asio/ssl/dtls/context.hpp"
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include "asio/ssl/dtls/socket.hpp"
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_context.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include "asio/ssl/dtls/acceptor.hpp"
#else  // ASIO_DTLS_USE_BOOST
#include "asio/ssl/dtls/context.hpp"
#include "asio/ssl/context.hpp"
#include "asio/ssl/context_base.hpp"
#include "asio/ssl/error.hpp"
#include "asio/ssl/rfc2818_verification.hpp"
#include "asio/ssl/dtls/socket.hpp"
#include "asio/ssl/stream_base.hpp"
#include "asio/ssl/verify_context.hpp"
#include "asio/ssl/verify_mode.hpp"
#include "asio/ssl/dtls/acceptor.hpp"
#endif // ASIO_DTLS_USE_BOOST

#endif // ASIO_DTLS_HPP
