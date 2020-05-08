#pragma once
#include <asio.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <vector>

#include "crow/http_parser_merged.h"

#include "crow/parser.h"
#include "crow/http_response.h"
#include "crow/logging.h"
#include "crow/settings.h"
#include "crow/dumb_timer_queue.h"
#include "crow/middleware_context.h"
#include "crow/socket_adaptors.h"

namespace crow
{
    using tcp = asio::ip::tcp;

    namespace detail
    {
        template <typename MW>
        struct check_before_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_before_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::before_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3_const
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) const = &T::after_handle
            >
            struct get
            { };
        };

        template <typename MW>
        struct check_after_handle_arity_3
        {
            template <typename T,
                void (T::*)(request&, response&, typename MW::context&) = &T::after_handle
            >
            struct get
            { };
        };

        template <typename T>
        struct is_before_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_before_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename T>
        struct is_after_handle_arity_3_impl
        {
            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3_const<T>::template get<C>*);

            template <typename C>
            static std::true_type f(typename check_after_handle_arity_3<T>::template get<C>*);

            template <typename C>
            static std::false_type f(...);

        public:
            static const bool value = decltype(f<T>(nullptr))::value;
        };

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& /*parent_ctx*/)
        {
            mw.before_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_before_handle_arity_3_impl<MW>::value>::type
        before_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& /*parent_ctx*/)
        {
            mw.before_handle(req, res, ctx.template get<MW>());
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<!is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& /*parent_ctx*/)
        {
            mw.after_handle(req, res, ctx.template get<MW>(), ctx);
        }

        template <typename MW, typename Context, typename ParentContext>
        typename std::enable_if<is_after_handle_arity_3_impl<MW>::value>::type
        after_handler_call(MW& mw, request& req, response& res, Context& ctx, ParentContext& /*parent_ctx*/)
        {
            mw.after_handle(req, res, ctx.template get<MW>());
        }

        template <size_t N, typename Context, typename Container, typename CurrentMW, typename ... Middlewares>
        bool middleware_call_helper(Container& middlewares, request& req, response& res, Context& ctx)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            before_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));

            if (res.is_completed())
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            if (middleware_call_helper<N+1, Context, Container, Middlewares...>(middlewares, req, res, ctx))
            {
                after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
                return true;
            }

            return false;
        }

        template <size_t N, typename Context, typename Container>
        bool middleware_call_helper(Container& /*middlewares*/, request& /*req*/, response& /*res*/, Context& /*ctx*/)
        {
            return false;
        }

        template <size_t N, typename Context, typename Container>
        typename std::enable_if<(N==0)>::type
        after_handlers_call_helper(Container& /*middlewares*/, Context& /*context*/, request& /*req*/, response& /*res*/)
        {
        }

        template <size_t N, typename Context, typename Container>
        typename std::enable_if<(N==1)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<0>;
            using CurrentMW = typename std::tuple_element<0, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<0>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
        }

        template <size_t N, typename Context, typename Container>
        typename std::enable_if<(N>1)>::type after_handlers_call_helper(Container& middlewares, Context& ctx, request& req, response& res)
        {
            using parent_context_t = typename Context::template partial<N-1>;
            using CurrentMW = typename std::tuple_element<N-1, typename std::remove_reference<Container>::type>::type;
            after_handler_call<CurrentMW, Context, parent_context_t>(std::get<N-1>(middlewares), req, res, ctx, static_cast<parent_context_t&>(ctx));
            after_handlers_call_helper<N-1, Context, Container>(middlewares, ctx, req, res);
        }
    }

#ifdef CROW_ENABLE_DEBUG
    static std::atomic<int> connectionCount;
#endif
    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection : public std::enable_shared_from_this<Connection<Adaptor, Handler, Middlewares...>>
    {
    public:
        Connection(
            asio::io_context& io_context,
            Handler* handler,
            const std::string& server_name,
            std::tuple<Middlewares...>* middlewares,
            std::function<std::string()>& get_cached_date_str_f,
            detail::dumb_timer_queue& timer_queue,
            typename Adaptor::context* adaptor_ctx_
            )
            : adaptor_(io_context, adaptor_ctx_),
            handler_(handler),
            parser_(this),
            server_name_(server_name),
            middlewares_(middlewares),
            get_cached_date_str(get_cached_date_str_f),
            timer_queue(timer_queue)
        {
#ifdef CROW_ENABLE_DEBUG
            connectionCount ++;
            CROW_LOG_DEBUG << "Connection open, total " << connectionCount << ", " << this;
#endif
        }

        ~Connection()
        {
            res_.complete_request_handler_ = nullptr;
            cancel_deadline_timer();
#ifdef CROW_ENABLE_DEBUG
            connectionCount --;
            CROW_LOG_DEBUG << "Connection closed, total " << connectionCount << ", " << this;
#endif
        }

        decltype(std::declval<Adaptor>().raw_socket())& socket()
        {
            return adaptor_.raw_socket();
        }

        void start()
        {
            auto self = this->shared_from_this();
            adaptor_.start([this, self](const asio::error_code& ec) {
                if (!ec)
                {
                    start_deadline();

                    do_read();
                }
            });
        }

        void handle_header()
        {
            // HTTP 1.1 Expect: 100-continue
            if (parser_.check_version(1, 1) && parser_.headers.count(HTTPField::Expect) && get_header_value(parser_.headers, HTTPField::Expect) == "100-continue")
            {
                buffers_.clear();
                static const char expect_100_continue[] = "HTTP/1.1 100 Continue\r\n\r\n";
                buffers_.emplace_back(expect_100_continue, sizeof(expect_100_continue) - 1);
                do_write();
            }
        }

        void handle()
        {
            cancel_deadline_timer();
            bool is_invalid_request = false;
            add_keep_alive_ = false;

            req_ = std::move(parser_.to_request());
            request& req = req_;
            response& res = res_;

            if (parser_.check_version(1, 0))
            {
                // HTTP/1.0
                auto it = req.headers.find(HTTPField::Connection);
                if (it != req.headers.end())
                {
                    if (utility::iequals(it->second, "Keep-Alive"))
                        add_keep_alive_ = true;
                }
                else
                    close_connection_ = true;
            }
            else if (parser_.check_version(1, 1))
            {
                // HTTP/1.1
                auto it = req.headers.find(HTTPField::Connection);
                if (it != req.headers.end())
                {
                    if (it->second == "close")
                        close_connection_ = true;
                    else if (utility::iequals(it->second, "Keep-Alive"))
                        add_keep_alive_ = true;
                }

                it = req.headers.find(HTTPField::Host);
                if (it == req.headers.end())
                {
                    is_invalid_request = true;
                    res = response(400);
                }

                if (parser_.is_upgrade())
                {
                    it = req.headers.find(HTTPField::Upgrade);
                    if (it != req.headers.end() && it->second == "h2c")
                    {
                        // TODO HTTP/2
                        // currently, ignore upgrade header
                    }
                    else
                    {
                        close_connection_ = true;
                        handler_->handle_upgrade(req, res, std::move(adaptor_));
                        return;
                    }
                }
            }

            //CROW_LOG_INFO << "Request: " << boost::lexical_cast<std::string>(adaptor_.remote_endpoint()) << " " << this << " HTTP/" << parser_.http_major << "." << parser_.http_minor << ' '
            // << method_name(req.method) << " " << req.url;


            need_to_call_after_handlers_ = false;
            if (!is_invalid_request)
            {
                res.complete_request_handler_ = []{};
                res.is_alive_helper_ = [this]()->bool{ return adaptor_.is_open(); };

                ctx_ = detail::context<Middlewares...>();
                req.middleware_context = (void*)&ctx_;
                req.io_context = &adaptor_.get_io_context();
                detail::middleware_call_helper<0, decltype(ctx_), decltype(*middlewares_), Middlewares...>(*middlewares_, req, res, ctx_);

                if (!res.completed_)
                {
                    res.complete_request_handler_ = [this]{ this->complete_request(); };
                    need_to_call_after_handlers_ = true;
                    handler_->handle(req, res);
                    if (add_keep_alive_)
                        res.set_header(HTTPField::Connection, "Keep-Alive");
                }
                else
                {
                    complete_request();
                }
            }
            else
            {
                complete_request();
            }
        }

        void complete_request()
        {
            CROW_LOG_INFO << "Response: " << this << ' ' << req_.raw_url << ' ' << res_.code << ' ' << close_connection_;

            if (need_to_call_after_handlers_)
            {
                need_to_call_after_handlers_ = false;

                // call all after_handler of middlewares
                detail::after_handlers_call_helper<
                    (sizeof...(Middlewares)),
                    decltype(ctx_),
                    decltype(*middlewares_)>
                (*middlewares_, ctx_, req_, res_);
            }

            //auto self = this->shared_from_this();
            res_.complete_request_handler_ = nullptr;

            if (!adaptor_.is_open())
            {
                //CROW_LOG_DEBUG << this << " delete (socket is closed) " << is_reading << ' ' << is_writing;
                return;
            }

            static std::unordered_map<int, std::string> statusCodes = {
                {200, "HTTP/1.1 200 OK\r\n"},
                {201, "HTTP/1.1 201 Created\r\n"},
                {202, "HTTP/1.1 202 Accepted\r\n"},
                {204, "HTTP/1.1 204 No Content\r\n"},

                {300, "HTTP/1.1 300 Multiple Choices\r\n"},
                {301, "HTTP/1.1 301 Moved Permanently\r\n"},
                {302, "HTTP/1.1 302 Moved Temporarily\r\n"},
                {304, "HTTP/1.1 304 Not Modified\r\n"},

                {400, "HTTP/1.1 400 Bad Request\r\n"},
                {401, "HTTP/1.1 401 Unauthorized\r\n"},
                {403, "HTTP/1.1 403 Forbidden\r\n"},
                {404, "HTTP/1.1 404 Not Found\r\n"},
                {413, "HTTP/1.1 413 Payload Too Large\r\n"},
                {422, "HTTP/1.1 422 Unprocessable Entity\r\n"},
                {429, "HTTP/1.1 429 Too Many Requests\r\n"},

                {500, "HTTP/1.1 500 Internal Server Error\r\n"},
                {501, "HTTP/1.1 501 Not Implemented\r\n"},
                {502, "HTTP/1.1 502 Bad Gateway\r\n"},
                {503, "HTTP/1.1 503 Service Unavailable\r\n"},
            };

            static const char seperator[] = ": ";
            static const char crlf[] = "\r\n";

            buffers_.clear();
            buffers_.reserve(4*(res_.headers.size()+5)+3);

            if (statusCodes.find(res_.code) == statusCodes.end())
                res_.code = 500;

            {
                auto& status = statusCodes.find(res_.code)->second;
                buffers_.emplace_back(status.data(), status.size());
            }

            if (res_.code >= 400 && res_.body.empty())
                res_.body = statusCodes[res_.code].substr(9);

            for(auto& kv : res_.headers)
            {
                auto& s = detail::field_to_string(kv.first);
                buffers_.emplace_back(s.data(), s.size());
                buffers_.emplace_back(seperator, sizeof(seperator) - 1);
                buffers_.emplace_back(kv.second.data(), kv.second.size());
                buffers_.emplace_back(crlf, sizeof(crlf) - 1);
            }

            if (res_.headers.find(HTTPField::Content_Length) == res_.headers.end())
            {
                content_length_ = std::to_string(res_.body.size());
                static const char content_length_tag[] = "Content-Length: ";
                buffers_.emplace_back(content_length_tag, sizeof(content_length_tag) - 1);
                buffers_.emplace_back(content_length_.data(), content_length_.size());
                buffers_.emplace_back(crlf, sizeof(crlf) - 1);
            }

            if (res_.headers.find(HTTPField::Server) == res_.headers.end())
            {
                static const char server_tag[] = "Server: ";
                buffers_.emplace_back(server_tag, sizeof(server_tag) - 1);
                buffers_.emplace_back(server_name_.data(), server_name_.size());
                buffers_.emplace_back(crlf, sizeof(crlf) - 1);
            }

            if (res_.headers.find(HTTPField::Date) == res_.headers.end())
            {
                static const char date_tag[] = "Date: ";
                date_str_ = get_cached_date_str();
                buffers_.emplace_back(date_tag, sizeof(date_tag) - 1);
                buffers_.emplace_back(date_str_.data(), date_str_.size());
                buffers_.emplace_back(crlf, sizeof(crlf) - 1);
            }

            if (add_keep_alive_)
            {
                static const char keep_alive_tag[] = "Connection: Keep-Alive";
                buffers_.emplace_back(keep_alive_tag, sizeof(keep_alive_tag) - 1);
                buffers_.emplace_back(crlf, sizeof(crlf) - 1);
            }

            buffers_.emplace_back(crlf, sizeof(crlf) - 1);

            res_body_copy_.swap(res_.body);
            buffers_.emplace_back(res_body_copy_.data(), res_body_copy_.size());

            do_write();

            if (need_to_start_read_after_complete_)
            {
                need_to_start_read_after_complete_ = false;
                start_deadline();
                do_read();
            }
        }

    private:
        void do_read()
        {
            auto self = this->shared_from_this();
            is_reading = true;
            adaptor_.socket().async_read_some(asio::buffer(buffer_),
                [this, self](const asio::error_code& ec, std::size_t bytes_transferred)
                {
                    bool error_while_reading = true;
                    if (!ec)
                    {
                        bool ret = parser_.feed(buffer_.data(), bytes_transferred);
                        if (ret && adaptor_.is_open())
                        {
                            error_while_reading = false;
                        }
                    }

                    if (error_while_reading)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        adaptor_.close();
                        is_reading = false;
                        CROW_LOG_DEBUG << this << " from read(1)";
                    }
                    else if (close_connection_)
                    {
                        cancel_deadline_timer();
                        parser_.done();
                        is_reading = false;
                        // adaptor will close after write
                    }
                    else if (!need_to_call_after_handlers_)
                    {
                        start_deadline();
                        do_read();
                    }
                    else
                    {
                        // res will be completed later by user
                        need_to_start_read_after_complete_ = true;
                    }
                });
        }

        void do_write()
        {
            auto self = this->shared_from_this();
            is_writing = true;
            asio::async_write(adaptor_.socket(), buffers_,
                [this, self](const asio::error_code& ec, std::size_t /*bytes_transferred*/)
                {
                    is_writing = false;
                    res_.clear();
                    res_body_copy_.clear();
                    if (!ec)
                    {
                        if (close_connection_)
                        {
                            adaptor_.close();
                            CROW_LOG_DEBUG << this << " from write(1)";
                        }
                    }
                    else
                    {
                        CROW_LOG_DEBUG << this << " from write(2)";
                    }
                });
        }

        void cancel_deadline_timer()
        {
            CROW_LOG_DEBUG << this << " timer cancelled: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
            timer_queue.cancel(timer_cancel_key_);
        }

        void start_deadline(/*int timeout = 5*/)
        {
            cancel_deadline_timer();

            timer_cancel_key_ = timer_queue.add([this]
            {
                if (!adaptor_.is_open())
                {
                    return;
                }
                adaptor_.close();
            });
            CROW_LOG_DEBUG << this << " timer added: " << timer_cancel_key_.first << ' ' << timer_cancel_key_.second;
        }

    private:
        Adaptor adaptor_;
        Handler* handler_;

        std::array<char, 4096> buffer_;

        HTTPParser<Connection> parser_;
        request req_;
        response res_;

        bool close_connection_ = false;

        const std::string& server_name_;
        std::vector<asio::const_buffer> buffers_;

        std::string content_length_;
        std::string date_str_;
        std::string res_body_copy_;

        //asio::deadline_timer deadline_;
        detail::dumb_timer_queue::key timer_cancel_key_;

        bool is_reading{};
        bool is_writing{};
        bool need_to_call_after_handlers_{};
        bool need_to_start_read_after_complete_{};
        bool add_keep_alive_{};

        std::tuple<Middlewares...>* middlewares_;
        detail::context<Middlewares...> ctx_;

        std::function<std::string()>& get_cached_date_str;
        detail::dumb_timer_queue& timer_queue;
    };

}
