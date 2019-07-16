#include "client.h"

#include <iostream>

const char buffer[] = "Hello world!";

Client::Client(boost::asio::io_context& context,
               boost::asio::ssl::dtls::context& ctx,
               boost::asio::ip::udp::endpoint& ep)
    : m_ctx(ctx)
    , m_dtls_con(context, ctx)
    , m_recbuffer()
{
    m_dtls_con.lowest_layer().connect(ep); // auch Async möglich

    m_dtls_con.async_handshake(boost::asio::ssl::stream_base::client,
      [this](boost::system::error_code ec){handshake_completed(ec);});
}

void Client::handshake_completed(boost::system::error_code ec)
{
    if(ec)
    {
        std::cout << "Handshake failed: " << ec.message() << std::endl;
    }
    else
    {
        m_dtls_con.async_send(
            boost::asio::const_buffers_1(buffer, std::strlen(buffer)),
            [this](const boost::system::error_code &ec, std::size_t size){
                sent(ec, size);
            });
    }
}

void Client::sent(boost::system::error_code ec, std::size_t size)
{
    if(ec)
    {
        std::cout << "Failed to send: " << ec.message() << std::endl;
    }
    else
    {
        std::cout << "Sent " << size << " bytes of data." << std::endl;

        m_dtls_con.async_receive(
            boost::asio::buffer(m_recbuffer, sizeof(m_recbuffer)),
            [this](boost::system::error_code ec, std::size_t s)
            {
                received(ec, s);
            });
    }
}

void Client::received(boost::system::error_code ec, std::size_t size)
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
