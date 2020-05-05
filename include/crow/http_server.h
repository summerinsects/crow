#pragma once

#include <chrono>
#include <asio.hpp>
#ifdef CROW_ENABLE_SSL
#include <asio/ssl.hpp>
#endif
#include <cstdint>
#include <atomic>
#include <future>
#include <vector>

#include <memory>

#include "crow/http_connection.h"
#include "crow/logging.h"
#include "crow/dumb_timer_queue.h"

namespace crow
{
    using tcp = asio::ip::tcp;
    using tick_timer = asio::system_timer;

    template <typename Handler, typename Adaptor = SocketAdaptor, typename ... Middlewares>
    class Server
    {
    public:
        Server(Handler* handler, std::string bindaddr, uint16_t port, std::tuple<Middlewares...>* middlewares = nullptr, uint16_t concurrency = 1, typename Adaptor::context* adaptor_ctx = nullptr)
            : acceptor_(io_context_, tcp::endpoint(asio::ip::make_address(bindaddr), port)),
            signals_(io_context_, SIGINT, SIGTERM),
            tick_timer_(io_context_),
            handler_(handler),
            concurrency_(concurrency),
            port_(port),
            bindaddr_(std::move(bindaddr)),
            middlewares_(middlewares),
            adaptor_ctx_(adaptor_ctx)
        {
        }

        void set_tick_function(std::chrono::milliseconds d, std::function<void()> f)
        {
            tick_interval_ = std::move(d);
            tick_function_ = std::move(f);
        }

        void on_tick()
        {
            tick_function_();
            tick_timer_.expires_after(tick_timer::duration(std::chrono::milliseconds(tick_interval_.count())));
            tick_timer_.async_wait([this](const asio::error_code& ec)
                    {
                        if (ec)
                            return;
                        on_tick();
                    });
        }

        void run()
        {
            if (concurrency_ < 0)
                concurrency_ = 1;

            for(int i = 0; i < concurrency_;  i++)
                io_context_pool_.emplace_back(new asio::io_context());
            get_cached_date_str_pool_.resize(concurrency_);
            timer_queue_pool_.resize(concurrency_);

            std::vector<std::future<void>> v;
            std::atomic<int> init_count(0);
            for(uint16_t i = 0; i < concurrency_; i ++)
                v.push_back(
                        std::async(std::launch::async, [this, i, &init_count]{

                            // thread local date string get function
                            auto last = std::chrono::steady_clock::now();

                            std::string date_str = utility::rfc822_format(time(nullptr));
                            get_cached_date_str_pool_[i] = [&]()->std::string
                            {
                                if (std::chrono::steady_clock::now() - last >= std::chrono::seconds(1))
                                {
                                    last = std::chrono::steady_clock::now();
                                    date_str = utility::rfc822_format(time(nullptr));
                                }
                                return date_str;
                            };

                            // initializing timer queue
                            detail::dumb_timer_queue timer_queue;
                            timer_queue_pool_[i] = &timer_queue;

                            timer_queue.set_io_context(*io_context_pool_[i]);
                            tick_timer timer(*io_context_pool_[i]);
                            timer.expires_after(tick_timer::duration(std::chrono::seconds(1)));

                            std::function<void(const asio::error_code& ec)> handler;
                            handler = [&](const asio::error_code& ec){
                                if (ec)
                                    return;
                                timer_queue.process();
                                timer.expires_after(tick_timer::duration(std::chrono::seconds(1)));
                                timer.async_wait(handler);
                            };
                            timer.async_wait(handler);

                            init_count ++;
                            while(1)
                            {
                                try
                                {
                                    if (io_context_pool_[i]->run() == 0)
                                    {
                                        // when io_context.run returns 0, there are no more works to do.
                                        break;
                                    }
                                } catch(std::exception& e)
                                {
                                    CROW_LOG_ERROR << "Worker Crash: An uncaught exception occurred: " << e.what();
                                }
                            }
                        }));

            if (tick_function_ && tick_interval_.count() > 0)
            {
                tick_timer_.expires_after(tick_timer::duration(std::chrono::milliseconds(tick_interval_.count())));
                tick_timer_.async_wait([this](const asio::error_code& ec)
                        {
                            if (ec)
                                return;
                            on_tick();
                        });
            }

            CROW_LOG_INFO << server_name_ << " server is running at " << bindaddr_ <<":" << port_
                          << " using " << concurrency_ << " threads";
            CROW_LOG_INFO << "Call `app.loglevel(crow::LogLevel::Warning)` to hide Info level logs.";

            signals_.async_wait(
                [&](const asio::error_code& /*error*/, int /*signal_number*/){
                    stop();
                });

            while(concurrency_ != init_count)
                std::this_thread::yield();

            do_accept();

            std::thread([this]{
                io_context_.run();
                CROW_LOG_INFO << "Exiting.";
            }).join();
        }

        void stop()
        {
            io_context_.stop();
            for(auto& io_context:io_context_pool_)
                io_context->stop();
        }

    private:
        asio::io_context& pick_io_context()
        {
            // TODO load balancing
            roundrobin_index_++;
            if (roundrobin_index_ >= io_context_pool_.size())
                roundrobin_index_ = 0;
            return *io_context_pool_[roundrobin_index_];
        }

        void do_accept()
        {
            asio::io_context& is = pick_io_context();
            auto conn = std::make_shared<Connection<Adaptor, Handler, Middlewares...>>(
                is, handler_, server_name_, middlewares_,
                get_cached_date_str_pool_[roundrobin_index_], *timer_queue_pool_[roundrobin_index_],
                adaptor_ctx_);
            auto p = conn->shared_from_this();
            acceptor_.async_accept(p->socket(),
                [this, p, &is](asio::error_code ec)
                {
                    if (!ec)
                    {
                        asio::post(is, [p]
                        {
                            p->start();
                        });
                    }
                    do_accept();
                });
        }

    private:
        asio::io_context io_context_;
        std::vector<std::unique_ptr<asio::io_context>> io_context_pool_;
        std::vector<detail::dumb_timer_queue*> timer_queue_pool_;
        std::vector<std::function<std::string()>> get_cached_date_str_pool_;
        tcp::acceptor acceptor_;
        asio::signal_set signals_;
        tick_timer tick_timer_;

        Handler* handler_;
        uint16_t concurrency_{1};
        std::string server_name_ = "Crow/0.1";
        uint16_t port_;
        std::string bindaddr_;
        unsigned int roundrobin_index_{};

        std::chrono::milliseconds tick_interval_;
        std::function<void()> tick_function_;

        std::tuple<Middlewares...>* middlewares_;

#ifdef CROW_ENABLE_SSL
        bool use_ssl_{false};
        asio::ssl::context ssl_context_{asio::ssl::context::sslv23};
#endif
        typename Adaptor::context* adaptor_ctx_;
    };
}
