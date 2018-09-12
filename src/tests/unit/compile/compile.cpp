#include <array>
#include <asio/ip/udp.hpp>
#include <asio/ssl/dtls/socket.hpp>

// These checks make sure using the classes compile. They are no
// example for proper usage.
void socket()
{
    asio::io_context ctx;
    asio::ssl::dtls::context dtls_ctx(asio::ssl::dtls::context::dtls_client);
    asio::error_code ec;
    std::array<char, 1> buffer_data{0};
    asio::mutable_buffer mbuffer(buffer_data.data(), buffer_data.size());
    asio::const_buffer buffer(buffer_data.data(), buffer_data.size());

    asio::ssl::dtls::socket<asio::ip::udp::socket> dtls_socket(ctx, dtls_ctx);
    dtls_socket.get_executor();
    dtls_socket.get_io_context();
    dtls_socket.get_io_service();

    dtls_socket.handshake(asio::ssl::stream_base::client);
    dtls_socket.handshake(asio::ssl::stream_base::client, ec);
    dtls_socket.handshake(asio::ssl::stream_base::client, buffer);
    dtls_socket.handshake(asio::ssl::stream_base::client, buffer, ec);

    dtls_socket.lowest_layer();
    dtls_socket.native_handle();
    dtls_socket.set_cookie_verify_callback([](const std::string &, const asio::ip::udp::endpoint&){return true;});
    dtls_socket.set_cookie_verify_callback([](const std::string &, const asio::ip::udp::endpoint&){return true;}, ec);

    dtls_socket.set_mtu(500);
    dtls_socket.set_mtu(500, ec);

    dtls_socket.set_verify_depth(0);
    dtls_socket.set_verify_depth(0, ec);

    dtls_socket.set_verify_mode(asio::ssl::verify_none);
    dtls_socket.set_verify_mode(asio::ssl::verify_none, ec);

    dtls_socket.shutdown();
    dtls_socket.shutdown(ec);

    dtls_socket.async_handshake(asio::ssl::stream_base::client,
                                [](const asio::error_code &){});
    dtls_socket.async_handshake(asio::ssl::stream_base::client, buffer,
                                [](const asio::error_code &, size_t){});

    dtls_socket.async_receive(mbuffer, [](const asio::error_code &, size_t){});

    dtls_socket.async_send(buffer, [](const asio::error_code &, size_t){});

    dtls_socket.async_shutdown([](const asio::error_code&){});

    dtls_socket.next_layer();

    dtls_socket.receive(mbuffer);
    dtls_socket.receive(mbuffer, ec);

    dtls_socket.send(buffer);
    dtls_socket.send(buffer, ec);

    dtls_socket.set_cookie_generate_callback([](std::string &, const asio::ip::udp::endpoint&){return true;});
    dtls_socket.set_cookie_generate_callback([](std::string &, const asio::ip::udp::endpoint&){return true;}, ec);

    asio::ip::udp::socket s(ctx);
    dtls_socket.verify_cookie(s, buffer, ec, asio::ip::udp::endpoint{});
}
