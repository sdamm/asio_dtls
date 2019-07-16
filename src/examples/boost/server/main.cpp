#define ASIO_STANDALONE 1
#define ASIO_HEADER_ONLY 1


#include "asio/dtls.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <iostream>

bool generateCookie(std::string &cookie, const boost::asio::ip::udp::endpoint& ep)
{
    cookie = "Wasser";

    std::cout << "Cookie generated for endpoint: " << ep
              << " is " << cookie << std::endl;

    return true;
}

bool verifyCookie(const std::string &cookie, const boost::asio::ip::udp::endpoint& ep)
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
    typedef boost::asio::ssl::dtls::socket<DatagramSocketType> dtls_sock;
    typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;

    typedef std::vector<char> buffer_type;
    typedef boost::asio::detail::shared_ptr<buffer_type> buffer_ptr;

    DTLS_Server(boost::asio::execution_context &serv,
                boost::asio::ssl::dtls::context &ctx,
                typename DatagramSocketType::endpoint_type &ep)
        : m_acceptor(serv, ep)
        , ctx_(ctx)
    {
        m_acceptor.set_option(boost::asio::socket_base::reuse_address(true));

        m_acceptor.set_cookie_generate_callback(generateCookie);
        m_acceptor.set_cookie_verify_callback(verifyCookie);

        m_acceptor.bind(ep);
    }

    void listen()
    {
        dtls_sock_ptr socket(new dtls_sock(m_acceptor.get_executor(), ctx_));

        buffer_ptr buffer(new buffer_type(1500));

        boost::asio::error_code ec;

        m_acceptor.async_accept(*socket,
                                boost::asio::buffer(buffer->data(), buffer->size()),
          [this, socket, buffer](const boost::asio::error_code &ec, size_t size)
          {
            if(ec)
            {
                std::cout << "Error in Accept: " << ec.message() << std::endl;
            }
            else
            {
                auto callback =
                  [this, socket, buffer](const boost::system::error_code &ec, size_t)
                  {
                    handshake_completed(socket, ec);
                  };

                socket->async_handshake(dtls_sock::server,
                                        boost::asio::buffer(buffer->data(), size),
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
    void handshake_completed(dtls_sock_ptr socket, const boost::asio::error_code &ec)
    {
        if(ec)
        {
            std::cout << "Handshake Error: " << ec.message() << std::endl;
        }
        else
        {
            std::shared_ptr<std::vector<char>> tmp(new std::vector<char>(1500));

            socket->async_receive(boost::asio::buffer(tmp->data(), tmp->size()),
              [this, socket, tmp](const boost::asio::error_code &ec, size_t size)
              {
                encrypted_data_received(ec, size, socket, tmp);
              });
        }
    }

    void encrypted_data_received(const boost::asio::error_code &ec, size_t received,
                                 dtls_sock_ptr socket,
                                 std::shared_ptr<std::vector<char>> data)
    {
        if(!ec)
        {
            socket->async_send(boost::asio::buffer(data->data(), received),
              [this, data, socket](const boost::asio::error_code &ec, size_t)
              {
                encrypted_data_sent(ec, socket);
              });
        }
    }

    void encrypted_data_sent(const boost::asio::error_code &ec, dtls_sock_ptr socket)
    {
        if(!ec)
        {
            std::cout << "Data sent, closing connection." << std::endl;
            socket->async_shutdown([socket](const boost::asio::error_code&){});
        }
    }

    boost::asio::ssl::dtls::acceptor<DatagramSocketType> m_acceptor;
    boost::asio::ssl::dtls::context &ctx_;
};

int main()
{
    try
    {
        boost::asio::io_context context;

        auto listenAddress = boost::asio::ip::address::from_string("127.0.0.1");
        boost::asio::ip::udp::endpoint listenEndpoint(listenAddress, 5555);

        boost::asio::ssl::dtls::context ctx(boost::asio::ssl::dtls::context::dtls_server);

        ctx.set_options(boost::asio::ssl::dtls::context::cookie_exchange);

        ctx.use_certificate_file("cert.pem", boost::asio::ssl::context_base::pem);
        ctx.use_private_key_file("privkey.pem", boost::asio::ssl::context_base::pem);

        DTLS_Server<boost::asio::ip::udp::socket> server(context, ctx, listenEndpoint);
        server.listen();

        context.run();
    }
    catch (std::exception &ex)
    {
        std::cout << "Error: " << ex.what() << std::endl;
    }

    return 0;
}
