#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iterator>
#include <functional>
#include "crow/json_traits.h"

namespace crow
{
    namespace mustache
    {
        template <typename Json, typename Traits>
        class template_t;

        template <typename Json, typename Traits>
        template_t<Json, Traits> load(const std::string& filename);

        class invalid_template_exception : public std::exception
        {
            public:
            invalid_template_exception(const std::string& msg)
                : msg("crow::mustache error: " + msg)
            {
            }
            virtual const char* what() const throw()
            {
                return msg.c_str();
            }
            std::string msg;
        };

        enum class ActionType
        {
            Ignore,
            Tag,
            UnescapeTag,
            OpenBlock,
            CloseBlock,
            ElseBlock,
            Partial,
        };

        struct Action
        {
            intptr_t start;
            intptr_t end;
            intptr_t pos;
            ActionType t;
            Action(ActionType t, intptr_t start, intptr_t end, intptr_t pos = 0)
                : start(start), end(end), pos(pos), t(t)
            {}
        };

        template <typename Json, typename Traits = json_traits<Json>>
        class template_t
        {
        public:
            template_t(std::string body)
                : body_(std::move(body))
            {
                // {{ {{# {{/ {{^ {{! {{> {{=
                parse();
            }

        private:
            typedef Json context;

            std::string tag_name(const Action& action)
            {
                return body_.substr(action.start, action.end - action.start);
            }

            std::pair<bool, const context&> find_context(const std::string& name, const std::vector<const context*>& stack)
            {
                if (name == ".")
                {
                    return {true, *stack.back()};
                }
                intptr_t dotPosition = name.find(".");
                if (dotPosition == (intptr_t)name.npos)
                {
                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        if (Traits::is_object(**it))
                        {
                            if (Traits::count(**it, name))
                                return { true, Traits::at(**it, name) };
                        }
                    }
                }
                else
                {
                    std::vector<intptr_t> dotPositions;
                    dotPositions.push_back(-1);
                    while(dotPosition != (intptr_t)name.npos)
                    {
                        dotPositions.push_back(dotPosition);
                        dotPosition = name.find(".", dotPosition+1);
                    }
                    dotPositions.push_back(name.size());
                    std::vector<std::string> names;
                    names.reserve(dotPositions.size()-1);
                    for(intptr_t i = 1; i < (intptr_t)dotPositions.size(); i ++)
                        names.emplace_back(name.substr(dotPositions[i-1]+1, dotPositions[i]-dotPositions[i-1]-1));

                    for(auto it = stack.rbegin(); it != stack.rend(); ++it)
                    {
                        const context* view = *it;
                        bool found = true;
                        for(auto jt = names.begin(); jt != names.end(); ++jt)
                        {
                            if (Traits::is_object(*view)
                                && Traits::count(*view, *jt))
                            {
                                view = &Traits::at(*view, *jt);
                            }
                            else
                            {
                                found = false;
                                break;
                            }
                        }
                        if (found)
                            return {true, *view};
                    }

                }

                static context empty_str = Traits::empty_string();
                return {false, empty_str};
            }

            void escape(const std::string& in, std::string& out)
            {
                out.reserve(out.size() + in.size());
                for(auto it = in.begin(); it != in.end(); ++it)
                {
                    switch(*it)
                    {
                        case '&': out += "&amp;"; break;
                        case '<': out += "&lt;"; break;
                        case '>': out += "&gt;"; break;
                        case '"': out += "&quot;"; break;
                        case '\'': out += "&#39;"; break;
                        case '/': out += "&#x2F;"; break;
                        default: out += *it; break;
                    }
                }
            }

            void render_internal(intptr_t actionBegin, intptr_t actionEnd, std::vector<const context*>& stack, std::string& out, intptr_t indent)
            {
                intptr_t current = actionBegin;

                if (indent)
                    out.insert(out.size(), indent, ' ');

                while(current < actionEnd)
                {
                    auto& fragment = fragments_[current];
                    auto& action = actions_[current];
                    render_fragment(fragment, indent, out);
                    switch(action.t)
                    {
                        case ActionType::Ignore:
                            // do nothing
                            break;
                        case ActionType::Partial:
                            {
                                std::string partial_name = tag_name(action);
                                auto partial_templ = load<Json, Traits>(partial_name);
                                intptr_t partial_indent = action.pos;
                                partial_templ.render_internal(0, partial_templ.fragments_.size()-1, stack, out, partial_indent?indent+partial_indent:0);
                            }
                            break;
                        case ActionType::UnescapeTag:
                        case ActionType::Tag:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                auto& ctx = optional_ctx.second;
                                if (Traits::is_null(ctx)) out += "null";
                                else if (Traits::is_false(ctx)) out += "false";
                                else if (Traits::is_true(ctx)) out += "true";
                                else if (Traits::is_number(ctx)) out += Traits::dump(ctx);
                                else if (Traits::is_string(ctx))
                                {
                                    if (action.t == ActionType::Tag)
                                        escape(Traits::get_string(ctx), out);
                                    else
                                        out += Traits::get_string(ctx);
                                }
                                else throw std::runtime_error("not implemented tag type" + std::to_string((int)Traits::get_type(ctx)));
                            }
                            break;
                        case ActionType::ElseBlock:
                            {
                                static context nullContext;
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    stack.emplace_back(&nullContext);
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                if (Traits::is_array(ctx))
                                {
                                    if (!Traits::empty(ctx))
                                        current = action.pos;
                                    else
                                        stack.emplace_back(&nullContext);
                                }
                                else if (Traits::is_false(ctx) || Traits::is_null(ctx))
                                    stack.emplace_back(&nullContext);
                                else
                                    current = action.pos;
                                break;
                            }
                        case ActionType::OpenBlock:
                            {
                                auto optional_ctx = find_context(tag_name(action), stack);
                                if (!optional_ctx.first)
                                {
                                    current = action.pos;
                                    break;
                                }

                                auto& ctx = optional_ctx.second;
                                if (Traits::is_array(ctx))
                                {
                                    if (!Traits::empty(ctx))
                                    {
                                        for (auto it = Traits::begin(ctx); it != Traits::end(ctx); ++it)
                                        {
                                            stack.push_back(&*it);
                                            render_internal(current + 1, action.pos, stack, out, indent);
                                            stack.pop_back();
                                        }
                                    }
                                    current = action.pos;
                                }
                                else if (Traits::is_number(ctx) || Traits::is_string(ctx) || Traits::is_object(ctx) || Traits::is_true(ctx))
                                    stack.push_back(&ctx);
                                else if (Traits::is_false(ctx) || Traits::is_null(ctx))
                                    current = action.pos;
                                else
                                    throw std::runtime_error("{{#: not implemented context type: " + std::to_string((int)Traits::get_type(ctx)));
                                break;
                            }
                        case ActionType::CloseBlock:
                            stack.pop_back();
                            break;
                        default:
                            throw std::runtime_error("not implemented " + std::to_string((int)action.t));
                    }
                    current++;
                }
                auto& fragment = fragments_[actionEnd];
                render_fragment(fragment, indent, out);
            }
            void render_fragment(const std::pair<intptr_t, intptr_t>& fragment, intptr_t indent, std::string& out)
            {
                if (indent)
                {
                    for(intptr_t i = fragment.first; i < fragment.second; i ++)
                    {
                        out += body_[i];
                        if (body_[i] == '\n' && i+1 != (intptr_t)body_.size())
                            out.insert(out.size(), indent, ' ');
                    }
                }
                else
                    out.insert(out.size(), body_, fragment.first, fragment.second-fragment.first);
            }
        public:
            std::string render()
            {
                context empty_ctx;
                std::vector<const context*> stack;
                stack.emplace_back(&empty_ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }
            std::string render(const context& ctx)
            {
                std::vector<const context*> stack;
                stack.emplace_back(&ctx);

                std::string ret;
                render_internal(0, fragments_.size()-1, stack, ret, 0);
                return ret;
            }

        private:

            void parse()
            {
                std::string tag_open = "{{";
                std::string tag_close = "}}";

                std::vector<intptr_t> blockPositions;

                size_t current = 0;
                while(1)
                {
                    size_t idx = body_.find(tag_open, current);
                    if (idx == body_.npos)
                    {
                        fragments_.emplace_back(current, body_.size());
                        actions_.emplace_back(ActionType::Ignore, 0, 0);
                        break;
                    }
                    fragments_.emplace_back(current, idx);

                    idx += tag_open.size();
                    size_t endIdx = body_.find(tag_close, idx);
                    if (endIdx == idx)
                    {
                        throw invalid_template_exception("empty tag is not allowed");
                    }
                    if (endIdx == body_.npos)
                    {
                        // error, no matching tag
                        throw invalid_template_exception("not matched opening tag");
                    }
                    current = endIdx + tag_close.size();
                    switch(body_[idx])
                    {
                        case '#':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::OpenBlock, idx, endIdx);
                            break;
                        case '/':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            {
                                auto& matched = actions_[blockPositions.back()];
                                if (body_.compare(idx, endIdx-idx,
                                        body_, matched.start, matched.end - matched.start) != 0)
                                {
                                    throw invalid_template_exception("not matched {{# {{/ pair: " +
                                        body_.substr(matched.start, matched.end - matched.start) + ", " +
                                        body_.substr(idx, endIdx-idx));
                                }
                                matched.pos = actions_.size();
                            }
                            actions_.emplace_back(ActionType::CloseBlock, idx, endIdx, blockPositions.back());
                            blockPositions.pop_back();
                            break;
                        case '^':
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            blockPositions.emplace_back(actions_.size());
                            actions_.emplace_back(ActionType::ElseBlock, idx, endIdx);
                            break;
                        case '!':
                            // do nothing action
                            actions_.emplace_back(ActionType::Ignore, idx+1, endIdx);
                            break;
                        case '>': // partial
                            idx++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Partial, idx, endIdx);
                            break;
                        case '{':
                            if (tag_open != "{{" || tag_close != "}}")
                                throw invalid_template_exception("cannot use triple mustache when delimiter changed");

                            idx ++;
                            if (body_[endIdx+2] != '}')
                            {
                                throw invalid_template_exception("{{{: }}} not matched");
                            }
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            current++;
                            break;
                        case '&':
                            idx ++;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::UnescapeTag, idx, endIdx);
                            break;
                        case '=':
                            // tag itself is no-op
                            idx ++;
                            actions_.emplace_back(ActionType::Ignore, idx, endIdx);
                            endIdx --;
                            if (body_[endIdx] != '=')
                                throw invalid_template_exception("{{=: not matching = tag: "+body_.substr(idx, endIdx-idx));
                            endIdx --;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx] == ' ') endIdx--;
                            endIdx++;
                            {
                                bool succeeded = false;
                                for(size_t i = idx; i < endIdx; i++)
                                {
                                    if (body_[i] == ' ')
                                    {
                                        tag_open = body_.substr(idx, i-idx);
                                        while(body_[i] == ' ') i++;
                                        tag_close = body_.substr(i, endIdx-i);
                                        if (tag_open.empty())
                                            throw invalid_template_exception("{{=: empty open tag");
                                        if (tag_close.empty())
                                            throw invalid_template_exception("{{=: empty close tag");

                                        if (tag_close.find(" ") != tag_close.npos)
                                            throw invalid_template_exception("{{=: invalid open/close tag: "+tag_open+" " + tag_close);
                                        succeeded = true;
                                        break;
                                    }
                                }
                                if (!succeeded)
                                    throw invalid_template_exception("{{=: cannot find space between new open/close tags");
                            }
                            break;
                        default:
                            // normal tag case;
                            while(body_[idx] == ' ') idx++;
                            while(body_[endIdx-1] == ' ') endIdx--;
                            actions_.emplace_back(ActionType::Tag, idx, endIdx);
                            break;
                    }
                }

                // removing standalones
                for(intptr_t i = actions_.size()-2; i >= 0; i --)
                {
                    if (actions_[i].t == ActionType::Tag || actions_[i].t == ActionType::UnescapeTag)
                        continue;
                    auto& fragment_before = fragments_[i];
                    auto& fragment_after = fragments_[i+1];
                    bool is_last_action = i == (intptr_t)actions_.size()-2;
                    bool all_space_before = true;
                    intptr_t j, k;
                    for(j = fragment_before.second-1;j >= fragment_before.first;j--)
                    {
                        if (body_[j] != ' ')
                        {
                            all_space_before = false;
                            break;
                        }
                    }
                    if (all_space_before && i > 0)
                        continue;
                    if (!all_space_before && body_[j] != '\n')
                        continue;
                    bool all_space_after = true;
                    for(k = fragment_after.first; k < (intptr_t)body_.size() && k < fragment_after.second; k ++)
                    {
                        if (body_[k] != ' ')
                        {
                            all_space_after = false;
                            break;
                        }
                    }
                    if (all_space_after && !is_last_action)
                        continue;
                    if (!all_space_after &&
                            !(
                                body_[k] == '\n'
                            ||
                                (body_[k] == '\r' &&
                                k + 1 < (int)body_.size() &&
                                body_[k+1] == '\n')))
                        continue;
                    if (actions_[i].t == ActionType::Partial)
                    {
                        actions_[i].pos = fragment_before.second - j - 1;
                    }
                    fragment_before.second = j+1;
                    if (!all_space_after)
                    {
                        if (body_[k] == '\n')
                            k++;
                        else
                            k += 2;
                        fragment_after.first = k;
                    }
                }
            }

            std::vector<std::pair<intptr_t,intptr_t>> fragments_;
            std::vector<Action> actions_;
            std::string body_;
        };

        template <typename Json, typename Traits = json_traits<Json>>
        inline template_t<Json, Traits> compile(std::string body)
        {
            return template_t<Json, Traits>(std::move(body));
        }

        namespace detail
        {
            inline std::string& get_template_base_directory_ref()
            {
                static std::string template_base_directory = "templates";
                return template_base_directory;
            }
        }

        inline std::string default_loader(const std::string& filename)
        {
            std::string path = detail::get_template_base_directory_ref();
            if (!(path.back() == '/' || path.back() == '\\'))
                path += '/';
            path += filename;
            std::ifstream inf(path);
            if (!inf)
                return {};
            return {std::istreambuf_iterator<char>(inf), std::istreambuf_iterator<char>()};
        }

        namespace detail
        {
            inline std::function<std::string (std::string)>& get_loader_ref()
            {
                static std::function<std::string (std::string)> loader = default_loader;
                return loader;
            }
        }

        inline void set_base(const std::string& path)
        {
            auto& base = detail::get_template_base_directory_ref();
            base = path;
            if (base.back() != '\\' &&
                base.back() != '/')
            {
                base += '/';
            }
        }

        inline void set_loader(std::function<std::string(std::string)> loader)
        {
            detail::get_loader_ref() = std::move(loader);
        }

        inline std::string load_text(const std::string& filename)
        {
            return detail::get_loader_ref()(filename);
        }

        template <typename Json, typename Traits = json_traits<Json>>
        inline template_t<Json, Traits> load(const std::string& filename)
        {
            return compile<Json, Traits>(detail::get_loader_ref()(filename));
        }
    }
}
