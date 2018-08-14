#ifndef CLIENT_H
#define CLIENT_H

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/dtls.hpp>
#include <asio/ip/udp.hpp>

class Client
{
public:
    Client(
        asio::io_service &service,
        asio::ssl::dtls::context &ctx,
        asio::ip::udp::endpoint &ep);

    void handshake_completed(asio::error_code ec);

    void sent(asio::error_code ec, std::size_t size);

    void received(asio::error_code ec, std::size_t size);

private:
    asio::ssl::dtls::context &m_ctx;
    asio::ssl::dtls::socket<asio::ip::udp::socket> m_dtls_con;
    char m_recbuffer[200];
};

#endif // CLIENT_H
