#define ASIO_STANDALONE 1
#   define ASIO_HEADER_ONLY 1
#include <asio/dtls.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <iostream>

/* Certificate validation works exactly the same as with SSL Streams.
 */
int callback(bool preverified, boost::asio::ssl::verify_context &ctx)
{
    (void) preverified;
    (void) ctx;

    return 1;
}

int main()
{
    boost::asio::io_context context;
    boost::asio::ssl::dtls::context ctx(boost::asio::ssl::dtls::context::dtls_client);

    std::cout << "Hello World client" << std::endl;

    ctx.set_verify_callback(callback);

    boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> dtls_con(context, ctx);

    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v4::loopback(), 5555);

    try
    {
        dtls_con.lowest_layer().connect(ep);

        dtls_con.handshake(boost::asio::ssl::stream_base::handshake_type::client);

        char buffer[] = "Hello world!";
        dtls_con.send(boost::asio::const_buffers_1(buffer, sizeof(buffer)));

        std::array<char, 200> recbuffer{};
        dtls_con.receive(boost::asio::buffer(recbuffer));

        std::cout << "Received: " << recbuffer.data() << std::endl;
    }
    catch(std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
}
