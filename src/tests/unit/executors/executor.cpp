#include <asio/bind_executor.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ssl/dtls/acceptor.hpp>
#include <asio/strand.hpp>

// These checks make sure using a strand compiles. They are no
// example for proper usage.
void dtls_socket()
{
    asio::io_context ctx;
    asio::ssl::dtls::context dtls_ctx{asio::ssl::dtls::context::dtls_client};
    asio::ssl::dtls::socket<asio::ip::udp::socket> sock(ctx, dtls_ctx);
    asio::io_context::strand str(ctx);

    auto handler_with_strand = asio::bind_executor(str, [](const asio::error_code&){});
    auto handler2_with_strand = asio::bind_executor(str, [](const asio::error_code&, size_t){});

    std::array<char, 1> buffer_data{0};
    asio::const_buffer buffer(buffer_data.data(), buffer_data.size());
    asio::mutable_buffer mbuffer(buffer_data.data(), buffer_data.size());

    sock.async_handshake(asio::ssl::stream_base::client, handler_with_strand);
    sock.async_handshake(asio::ssl::stream_base::client, buffer, handler2_with_strand);
    sock.async_receive(mbuffer, handler2_with_strand);
    sock.async_send(buffer, handler2_with_strand);
    sock.async_shutdown(handler_with_strand);
}

// These checks make sure using a strand compiles. They are no
// example for proper usage.
void dtls_acceptor()
{
    asio::io_context ctx;
    asio::ssl::dtls::context dtls_ctx{asio::ssl::dtls::context::dtls_server};
    asio::ip::udp::endpoint ep;
    asio::error_code ec;

    asio::ssl::dtls::acceptor<asio::ip::udp::socket> acceptor_test(ctx, ep);
    asio::ssl::dtls::socket<asio::ip::udp::socket> sock(ctx, dtls_ctx);

    asio::io_context::strand str(ctx);
    auto handler_with_strand = asio::bind_executor(str, [](const asio::error_code&, size_t){});

    std::array<char, 1> buffer_data{};
    acceptor_test.async_accept(sock, asio::mutable_buffer(buffer_data.data(), buffer_data.size()),
                               handler_with_strand, ec);
}
