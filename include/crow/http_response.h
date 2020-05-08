#pragma once
#include <string>
#include <unordered_map>

#include "crow/http_request.h"
#include "crow/common.h"
#include "crow/json_traits.h"

namespace crow
{
    template <typename Adaptor, typename Handler, typename ... Middlewares>
    class Connection;
    struct response
    {
        template <typename Adaptor, typename Handler, typename ... Middlewares>
        friend class crow::Connection;

        int code{200};
        std::string body;

        // `headers' stores HTTP headers.
        std::unordered_multimap<HTTPField, std::string> headers;

        void set_header(HTTPField key, std::string value)
        {
            headers.erase(key);
            headers.emplace(key, std::move(value));
        }

        void add_header(HTTPField key, std::string value)
        {
            headers.emplace(key, std::move(value));
        }

        const std::string& get_header_value(HTTPField key)
        {
            return crow::get_header_value(headers, key);
        }


        response() {}
        explicit response(int code) : code(code) {}
        response(std::string body) : body(std::move(body)) {}
        response(int code, std::string body) : code(code), body(std::move(body)) {}

        template <typename T, typename = std::enable_if<
            std::is_convertible<
                decltype(json_traits<T>::dump(std::declval<T>())),
                decltype(response::body)
            >::value>>
        response(const T& json) : body(json_traits<T>::dump(json))
        {
            set_header(HTTPField::Content_Type, "application/json");
        }

        response(response&& r)
        {
            *this = std::move(r);
        }

        response& operator = (const response& r) = delete;

        response& operator = (response&& r) noexcept
        {
            body = std::move(r.body);
            code = r.code;
            headers = std::move(r.headers);
            completed_ = r.completed_;
            return *this;
        }

        bool is_completed() const noexcept
        {
            return completed_;
        }

        void clear()
        {
            body.clear();
            code = 200;
            headers.clear();
            completed_ = false;
        }

        void redirect(std::string location)
        {
            code = 301;
            set_header(HTTPField::Location, std::move(location));
        }

        void write(const std::string& body_part)
        {
            body += body_part;
        }

        void end()
        {
            if (!completed_)
            {
                completed_ = true;

                if (complete_request_handler_)
                {
                    complete_request_handler_();
                }
            }
        }

        void end(const std::string& body_part)
        {
            body += body_part;
            end();
        }

        bool is_alive()
        {
            return is_alive_helper_ && is_alive_helper_();
        }

        private:
            bool completed_{};
            std::function<void()> complete_request_handler_;
            std::function<bool()> is_alive_helper_;
    };
}
