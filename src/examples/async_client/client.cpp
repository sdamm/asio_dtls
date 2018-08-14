#include "client.h"

#include <iostream>

const char buffer[] = "Hello world!";

Client::Client(asio::io_service& service,
               asio::ssl::dtls::context& ctx,
               asio::ip::udp::endpoint& ep)
    : m_ctx(ctx)
    , m_dtls_con(service, ctx)
{
    m_dtls_con.lowest_layer().connect(ep); // auch Async möglich

    m_dtls_con.async_handshake(asio::ssl::stream_base::client,
      [this](asio::error_code ec){handshake_completed(ec);});
}

void Client::handshake_completed(asio::error_code ec)
{
    if(ec)
    {
        std::cout << "Handshake failed: " << ec.message() << std::endl;
    }
    else
    {
        m_dtls_con.async_send(
            asio::const_buffers_1(buffer, std::strlen(buffer)),
            [this](const asio::error_code &ec, std::size_t size){
                sent(ec, size);
            });
    }
}

void Client::sent(asio::error_code ec, std::size_t size)
{
    if(ec)
    {
        std::cout << "Failed to send: " << ec.message() << std::endl;
    }
    else
    {
        std::cout << "Sent " << size << " bytes of data." << std::endl;

        m_dtls_con.async_receive(
            asio::buffer(m_recbuffer, sizeof(m_recbuffer)),
            [this](asio::error_code ec, std::size_t s)
            {
                received(ec, s);
            });
    }
}

void Client::received(asio::error_code ec, std::size_t size)
{
    if(ec)
    {
        std::cout << "Receive failed: " << ec.message() << std::endl;
    }
    else
    {
        std::string rec(m_recbuffer, size);

        std::cout << "Received " << rec << std::endl;
    }
}
