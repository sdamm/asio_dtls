#define ASIO_STANDALONE 1
#define ASIO_HEADER_ONLY 1


#include "asio/dtls.hpp"
#include <asio.hpp>
#include <functional>
#include <iostream>

bool generateCookie(std::string &cookie, const asio::ip::udp::endpoint& ep)
{
    cookie = "Wasser";

    std::cout << "Cookie generated for endpoint: " << ep
              << " is " << cookie << std::endl;

    return true;
}

bool verifyCookie(const std::string &cookie, const asio::ip::udp::endpoint& ep)
{
    std::cout << "Cookie provided for endpoint: " << ep
              << " is " << cookie
              << " should be " << "Wasser" << std::endl;
    return (cookie == "Wasser");
}


template <typename DatagramSocketType>
class DTLS_Server
{
public:
    typedef asio::ssl::dtls::socket<DatagramSocketType> dtls_sock;
    typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;

    typedef std::vector<char> buffer_type;
    typedef asio::detail::shared_ptr<buffer_type> buffer_ptr;

    DTLS_Server(asio::io_service &serv,
                asio::ssl::dtls::context &ctx,
                typename DatagramSocketType::endpoint_type &ep)
        : m_acceptor(serv, ep)
        , ctx_(ctx)
    {
        m_acceptor.set_option(asio::socket_base::reuse_address(true));

        m_acceptor.set_cookie_generate_callback(generateCookie);
        m_acceptor.set_cookie_verify_callback(verifyCookie);

        m_acceptor.bind(ep);
    }

    void listen()
    {
        dtls_sock_ptr socket(new dtls_sock(m_acceptor.get_service(), ctx_));

        buffer_ptr buffer(new buffer_type(1500));

        asio::error_code ec;

        m_acceptor.async_accept(*socket,
                                asio::buffer(buffer->data(), buffer->size()),
          [this, socket, buffer](const asio::error_code &ec, size_t size)
          {
            if(ec)
            {
                std::cout << "Error in Accept: " << ec.message() << std::endl;
            }
            else
            {
                auto callback =
                  [this, socket, buffer](const asio::error_code &ec, size_t)
                  {
                    handshake_completed(socket, ec);
                  };

                socket->async_handshake(dtls_sock::server,
                                        asio::buffer(buffer->data(), size),
                                        callback);

                listen();
            }
          }, ec);
        if(ec)
        {
            std::cout << "Failed: " << ec.message() << std::endl;
        }
    }

private:
    void handshake_completed(dtls_sock_ptr socket, const asio::error_code &ec)
    {
        if(ec)
        {
            std::cout << "Handshake Error: " << ec.message() << std::endl;
        }
        else
        {
            std::shared_ptr<std::vector<char>> tmp(new std::vector<char>(1500));

            socket->async_receive(asio::buffer(tmp->data(), tmp->size()),
              [this, socket, tmp](const asio::error_code &ec, size_t size)
              {
                encrypted_data_received(ec, size, socket, tmp);
              });
        }
    }

    void encrypted_data_received(const asio::error_code &ec, size_t received,
                                 dtls_sock_ptr socket,
                                 std::shared_ptr<std::vector<char>> data)
    {
        if(!ec)
        {
            socket->async_send(asio::buffer(data->data(), received),
              [this, data, socket](const asio::error_code &ec, size_t)
              {
                encrypted_data_sent(ec, socket);
              });
        }
    }

    void encrypted_data_sent(const asio::error_code &ec, dtls_sock_ptr socket)
    {
        if(!ec)
        {
            std::cout << "Data sent, closing connection." << std::endl;
            socket->async_shutdown([socket](const asio::error_code&){});
        }
    }

    asio::ssl::dtls::acceptor<DatagramSocketType> m_acceptor;
    asio::ssl::dtls::context &ctx_;
};

int main()
{
    try
    {
        asio::io_service service;

        auto listenAddress = asio::ip::address::from_string("127.0.0.1");
        asio::ip::udp::endpoint listenEndpoint(listenAddress, 5555);

        asio::ssl::dtls::context ctx(asio::ssl::dtls::context::dtls_server);

        ctx.set_options(asio::ssl::dtls::context::cookie_exchange);

        ctx.use_certificate_file("cert.pem", asio::ssl::context_base::pem);
        ctx.use_private_key_file("privkey.pem", asio::ssl::context_base::pem);

        DTLS_Server<asio::ip::udp::socket> server(service, ctx, listenEndpoint);
        server.listen();

        service.run();
    }
    catch (std::exception &ex)
    {
        std::cout << "Error: " << ex.what() << std::endl;
    }

    return 0;
}
