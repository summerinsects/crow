#pragma once

#include <unordered_map>
#include "crow/utility.h"

namespace crow
{
    namespace detail
    {
        static inline void hash_combine(std::size_t& lhs, std::size_t rhs)
        {
            lhs ^= (rhs + 0x9e3779b9 + (lhs << 6) + (lhs >> 2));
        }
    }

    struct ci_hash
    {
        size_t operator()(const std::string& key) const
        {
            std::size_t seed = 0;
            std::locale locale;

            for(auto c : key)
            {
                detail::hash_combine(seed, std::toupper(c, locale));
            }

            return seed;
        }
    };

    struct ci_key_eq
    {
        bool operator()(const std::string& l, const std::string& r) const
        {
            return utility::iequals(l, r);
        }
    };

    using ci_map = std::unordered_multimap<std::string, std::string, ci_hash, ci_key_eq>;
}
