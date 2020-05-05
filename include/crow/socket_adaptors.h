#pragma once
#include <asio.hpp>
#ifdef CROW_ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include "crow/settings.h"
namespace crow
{
    using tcp = asio::ip::tcp;

    struct SocketAdaptor
    {
        using context = void;
        SocketAdaptor(asio::io_context& io_context, context*)
            : socket_(io_context)
        {
        }

        asio::io_context& get_io_context()
        {
            return reinterpret_cast<asio::io_context&>(socket_.get_executor().context());
        }

        tcp::socket& raw_socket()
        {
            return socket_;
        }

        tcp::socket& socket()
        {
            return socket_;
        }

        tcp::endpoint remote_endpoint()
        {
            return socket_.remote_endpoint();
        }

        bool is_open()
        {
            return socket_.is_open();
        }

        void close()
        {
            asio::error_code ec;
            socket_.close(ec);
        }

        template <typename F>
        void start(F f)
        {
            f(asio::error_code());
        }

        tcp::socket socket_;
    };

#ifdef CROW_ENABLE_SSL
    struct SSLAdaptor
    {
        using context = asio::ssl::context;
        using ssl_socket_t = asio::ssl::stream<tcp::socket>;
        SSLAdaptor(asio::io_context& io_context, context* ctx)
            : ssl_socket_(new ssl_socket_t(io_context, *ctx))
        {
        }

        asio::ssl::stream<tcp::socket>& socket()
        {
            return *ssl_socket_;
        }

        tcp::socket::lowest_layer_type&
        raw_socket()
        {
            return ssl_socket_->lowest_layer();
        }

        tcp::endpoint remote_endpoint()
        {
            return raw_socket().remote_endpoint();
        }

        bool is_open()
        {
            return raw_socket().is_open();
        }

        void close()
        {
            asio::error_code ec;
            raw_socket().close(ec);
        }

        asio::io_context& get_io_context()
        {
            return reinterpret_cast<asio::io_context&>(raw_socket().get_executor().context());
        }

        template <typename F>
        void start(F f)
        {
            ssl_socket_->async_handshake(asio::ssl::stream_base::server,
                    [f](const asio::error_code& ec) {
                        f(ec);
                    });
        }

        std::unique_ptr<asio::ssl::stream<tcp::socket>> ssl_socket_;
    };
#endif
}
