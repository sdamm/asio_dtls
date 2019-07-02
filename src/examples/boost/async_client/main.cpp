#include "client.h"
#include <iostream>

int main()
{
    boost::asio::io_context service;
    boost::asio::ssl::dtls::context ctx(boost::asio::ssl::dtls::context::dtls_client);

#if VERIFY_CERTIFICATE
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(
        boost::asio::ssl::context_base::verify_peer
        | boost::asio::ssl::context_base::verify_fail_if_no_peer_cert);

    ctx.set_verify_callback(boost::asio::ssl::rfc2818_verification("127.0.0.1"));
#endif

    boost::asio::ip::address address(boost::asio::ip::address_v4::from_string("127.0.0.1"));
    boost::asio::ip::udp::endpoint ep(address, 5555);

    Client client(service, ctx, ep);

    service.run();
}
