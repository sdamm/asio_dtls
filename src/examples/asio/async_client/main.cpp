#include "client.h"
#include <iostream>

int main()
{
    asio::io_context context;
    asio::ssl::dtls::context ctx(asio::ssl::dtls::context::dtls_client);

#if VERIFY_CERTIFICATE
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(
        asio::ssl::context_base::verify_peer
        | asio::ssl::context_base::verify_fail_if_no_peer_cert);

    ctx.set_verify_callback(asio::ssl::rfc2818_verification("127.0.0.1"));
#endif

    asio::ip::address address(asio::ip::address_v4::from_string("127.0.0.1"));
    asio::ip::udp::endpoint ep(address, 5555);

    Client client(context, ctx, ep);

    context.run();
}
