#pragma once

namespace crow
{
    template <typename> struct json_traits;

    //template <> struct json_traits<json_value>
    //{
    //    typedef json_value value;
    //    typedef json_node_type value_type;
    //    typedef array::iterator iterator;
    //    typedef array::iterator const_iterator;
    //    static bool is_null(const value &v);
    //    static bool is_false(const value &v);
    //    static bool is_true(const value &v);
    //    static bool is_number(const value &v);
    //    static bool is_string(const value &v);
    //    static bool is_array(const value &v);
    //    static bool is_object(const value &v);
    //    static std::string dump(const value &v);
    //    static size_t count(const value &v, const char *name);
    //    static size_t count(const value &v, const std::string &name);
    //    static value &at(value &v, const char *name);
    //    static value &at(value &v, const std::string &name);
    //    static const value &at(const value &v, const char *name);
    //    static const value &at(const value &v, const std::string &name);
    //    static bool empty(const value &v);
    //    static iterator begin(value &v);
    //    static iterator end(value &v);
    //    static const_iterator begin(const value &v);
    //    static const_iterator end(const value &v);
    //    static value_type get_type(const value &v);
    //    static const char *get_string(const value &v);
    //    static value empty_string();
    //};
}
