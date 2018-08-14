#define ASIO_STANDALONE 1
#   define ASIO_HEADER_ONLY 1
#include <asio/dtls.hpp>
#include <asio/ip/udp.hpp>

#include <iostream>


using namespace std;

/* Certificate validation works exactly the same as with SSL Streams.
 */
int callback(bool preverified, asio::ssl::verify_context &ctx)
{
    (void) preverified;
    (void) ctx;

    return 1;
}

int main()
{
    asio::io_context service;
    asio::ssl::dtls::context ctx(asio::ssl::dtls::context::dtls_client);

    cout << "Hello World client" << std::endl;

    ctx.set_verify_callback(callback);

    asio::ssl::dtls::socket<asio::ip::udp::socket> dtls_con(service, ctx);

    asio::ip::udp::endpoint ep(asio::ip::address_v4::loopback(), 5555);

    try
    {
        dtls_con.lowest_layer().connect(ep);

        dtls_con.handshake(asio::ssl::stream_base::handshake_type::client);

        char buffer[] = "Hello world!";
        dtls_con.send(asio::const_buffers_1(buffer, sizeof(buffer)));

        char recbuffer[200];
        dtls_con.receive(asio::mutable_buffers_1(recbuffer, 200));

        cout << "Received: " << recbuffer << std::endl;
    }
    catch(std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
}
