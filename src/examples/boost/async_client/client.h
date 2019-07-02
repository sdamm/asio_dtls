#ifndef CLIENT_H
#define CLIENT_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <asio/dtls.hpp>
#include <boost/asio/ip/udp.hpp>

class Client
{
public:
    Client(
        boost::asio::io_service &service,
        boost::asio::ssl::dtls::context &ctx,
        boost::asio::ip::udp::endpoint &ep);

    void handshake_completed(boost::system::error_code ec);

    void sent(boost::asio::error_code ec, std::size_t size);

    void received(boost::asio::error_code ec, std::size_t size);

private:
    boost::asio::ssl::dtls::context &m_ctx;
    boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> m_dtls_con;
    char m_recbuffer[200];
};

#endif // CLIENT_H
