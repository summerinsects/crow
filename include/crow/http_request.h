#pragma once

#include <asio.hpp>

#include "crow/common.h"
#include "crow/query_string.h"

namespace crow
{
    template <typename T>
    inline const std::string& get_header_value(const T& headers, HTTPField key)
    {
        auto it = headers.find(key);
        if (it != headers.end())
        {
            return it->second;
        }
        static std::string empty;
        return empty;
    }

    struct DetachHelper;

    struct request
    {
        HTTPMethod method;
        std::string raw_url;
        std::string url;
        query_string url_params;
        std::unordered_multimap<HTTPField, std::string> headers;
        std::string body;

        void* middleware_context{};
        asio::io_context* io_context{};

        request()
            : method(HTTPMethod::Get)
        {
        }

        request(HTTPMethod method, std::string raw_url, std::string url, query_string url_params, std::unordered_multimap<HTTPField, std::string> headers, std::string body)
            : method(method), raw_url(std::move(raw_url)), url(std::move(url)), url_params(std::move(url_params)), headers(std::move(headers)), body(std::move(body))
        {
        }

        void add_header(HTTPField key, std::string value)
        {
            headers.emplace(key, std::move(value));
        }

        const std::string& get_header_value(HTTPField key) const
        {
            return crow::get_header_value(headers, key);
        }

        template<typename CompletionHandler>
        void post(CompletionHandler handler)
        {
            asio::post(io_context, std::forward<CompletionHandler>(handler));
        }

        template<typename CompletionHandler>
        void dispatch(CompletionHandler handler)
        {
            asio::dispatch(io_context, std::forward<CompletionHandler>(handler));
        }

    };
}
