#pragma once

#include <array>
#include <string>
#include <stdexcept>
#include <iostream>
#include <string.h>
#include "crow/utility.h"

namespace crow
{
    enum class HTTPMethod
    {
#ifndef DELETE
        DELETE = 0,
        GET,
        HEAD,
        POST,
        PUT,
        CONNECT,
        OPTIONS,
        TRACE,
        PATCH,
        PURGE,
#endif

        Delete = 0,
        Get,
        Head,
        Post,
        Put,
        Connect,
        Options,
        Trace,
        Patch,
        Purge,


        InternalMethodCount,
        // should not add an item below this line: used for array count
    };

    inline std::string method_name(HTTPMethod method)
    {
        switch(method)
        {
            case HTTPMethod::Delete:
                return "DELETE";
            case HTTPMethod::Get:
                return "GET";
            case HTTPMethod::Head:
                return "HEAD";
            case HTTPMethod::Post:
                return "POST";
            case HTTPMethod::Put:
                return "PUT";
            case HTTPMethod::Connect:
                return "CONNECT";
            case HTTPMethod::Options:
                return "OPTIONS";
            case HTTPMethod::Trace:
                return "TRACE";
            case HTTPMethod::Patch:
                return "PATCH";
            case HTTPMethod::Purge:
                return "PURGE";
            default:
                break;
        }
        return "invalid";
    }

    enum class ParamType
    {
        INT,
        UINT,
        DOUBLE,
        STRING,
        PATH,

        MAX
    };

    struct routing_params
    {
        std::vector<int64_t> int_params;
        std::vector<uint64_t> uint_params;
        std::vector<double> double_params;
        std::vector<std::string> string_params;

        void debug_print() const
        {
            std::cerr << "routing_params" << std::endl;
            for(auto i:int_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:uint_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto i:double_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
            for(auto& i:string_params)
                std::cerr<<i <<", " ;
            std::cerr<<std::endl;
        }

        template <typename T>
        T get(unsigned) const;

    };

    template<>
    inline int64_t routing_params::get<int64_t>(unsigned index) const
    {
        return int_params[index];
    }

    template<>
    inline uint64_t routing_params::get<uint64_t>(unsigned index) const
    {
        return uint_params[index];
    }

    template<>
    inline double routing_params::get<double>(unsigned index) const
    {
        return double_params[index];
    }

    template<>
    inline std::string routing_params::get<std::string>(unsigned index) const
    {
        return string_params[index];
    }

    enum class HTTPField : unsigned short
    {
        Unknown = 0,

        A_IM,
        Accept,
        Accept_Additions,
        Accept_Charset,
        Accept_Datetime,
        Accept_Encoding,
        Accept_Features,
        Accept_Language,
        Accept_Patch,
        Accept_Post,
        Accept_Ranges,
        Access_Control,
        Access_Control_Allow_Credentials,
        Access_Control_Allow_Headers,
        Access_Control_Allow_Methods,
        Access_Control_Allow_Origin,
        Access_Control_Expose_Headers,
        Access_Control_Max_Age,
        Access_Control_Request_Headers,
        Access_Control_Request_Method,
        Age,
        Allow,
        ALPN,
        Also_Control,
        Alt_Svc,
        Alt_Used,
        Alternate_Recipient,
        Alternates,
        Apparently_To,
        Apply_To_Redirect_Ref,
        Approved,
        Archive,
        Archived_At,
        Article_Names,
        Article_Updates,
        Authentication_Control,
        Authentication_Info,
        Authentication_Results,
        Authorization,
        Auto_Submitted,
        Autoforwarded,
        Autosubmitted,
        Base,
        Bcc,
        Body,
        C_Ext,
        C_Man,
        C_Opt,
        C_PEP,
        C_PEP_Info,
        Cache_Control,
        CalDAV_Timezones,
        Cancel_Key,
        Cancel_Lock,
        Cc,
        Close,
        Comments,
        Compliance,
        Connection,
        Content_Alternative,
        Content_Base,
        Content_Description,
        Content_Disposition,
        Content_Duration,
        Content_Encoding,
        Content_features,
        Content_ID,
        Content_Identifier,
        Content_Language,
        Content_Length,
        Content_Location,
        Content_MD5,
        Content_Range,
        Content_Return,
        Content_Script_Type,
        Content_Style_Type,
        Content_Transfer_Encoding,
        Content_Type,
        Content_Version,
        Control,
        Conversion,
        Conversion_With_Loss,
        Cookie,
        Cookie2,
        Cost,
        DASL,
        Date,
        Date_Received,
        DAV,
        Default_Style,
        Deferred_Delivery,
        Delivery_Date,
        Delta_Base,
        Depth,
        Derived_From,
        Destination,
        Differential_ID,
        Digest,
        Discarded_X400_IPMS_Extensions,
        Discarded_X400_MTS_Extensions,
        Disclose_Recipients,
        Disposition_Notification_Options,
        Disposition_Notification_To,
        Distribution,
        DKIM_Signature,
        DL_Expansion_History,
        Downgraded_Bcc,
        Downgraded_Cc,
        Downgraded_Disposition_Notification_To,
        Downgraded_Final_Recipient,
        Downgraded_From,
        Downgraded_In_Reply_To,
        Downgraded_Mail_From,
        Downgraded_Message_Id,
        Downgraded_Original_Recipient,
        Downgraded_Rcpt_To,
        Downgraded_References,
        Downgraded_Reply_To,
        Downgraded_Resent_Bcc,
        Downgraded_Resent_Cc,
        Downgraded_Resent_From,
        Downgraded_Resent_Reply_To,
        Downgraded_Resent_Sender,
        Downgraded_Resent_To,
        Downgraded_Return_Path,
        Downgraded_Sender,
        Downgraded_To,
        EDIINT_Features,
        Eesst_Version,
        Encoding,
        Encrypted,
        Errors_To,
        ETag,
        Expect,
        Expires,
        Expiry_Date,
        Ext,
        Followup_To,
        Forwarded,
        From,
        Generate_Delivery_Report,
        GetProfile,
        Hobareg,
        Host,
        HTTP2_Settings,
        If,
        If_Match,
        If_Modified_Since,
        If_None_Match,
        If_Range,
        If_Schedule_Tag_Match,
        If_Unmodified_Since,
        IM,
        Importance,
        In_Reply_To,
        Incomplete_Copy,
        Injection_Date,
        Injection_Info,
        Jabber_ID,
        Keep_Alive,
        Keywords,
        Label,
        Language,
        Last_Modified,
        Latest_Delivery_Time,
        Lines,
        Link,
        List_Archive,
        List_Help,
        List_ID,
        List_Owner,
        List_Post,
        List_Subscribe,
        List_Unsubscribe,
        List_Unsubscribe_Post,
        Location,
        Lock_Token,
        Man,
        Max_Forwards,
        Memento_Datetime,
        Message_Context,
        Message_ID,
        Message_Type,
        Meter,
        Method_Check,
        Method_Check_Expires,
        MIME_Version,
        MMHS_Acp127_Message_Identifier,
        MMHS_Authorizing_Users,
        MMHS_Codress_Message_Indicator,
        MMHS_Copy_Precedence,
        MMHS_Exempted_Address,
        MMHS_Extended_Authorisation_Info,
        MMHS_Handling_Instructions,
        MMHS_Message_Instructions,
        MMHS_Message_Type,
        MMHS_Originator_PLAD,
        MMHS_Originator_Reference,
        MMHS_Other_Recipients_Indicator_CC,
        MMHS_Other_Recipients_Indicator_To,
        MMHS_Primary_Precedence,
        MMHS_Subject_Indicator_Codes,
        MT_Priority,
        Negotiate,
        Newsgroups,
        NNTP_Posting_Date,
        NNTP_Posting_Host,
        Non_Compliance,
        Obsoletes,
        Opt,
        Optional,
        Optional_WWW_Authenticate,
        Ordering_Type,
        Organization,
        Origin,
        Original_Encoded_Information_Types,
        Original_From,
        Original_Message_ID,
        Original_Recipient,
        Original_Sender,
        Original_Subject,
        Originator_Return_Address,
        Overwrite,
        P3P,
        Path,
        PEP,
        Pep_Info,
        PICS_Label,
        Position,
        Posting_Version,
        Pragma,
        Prefer,
        Preference_Applied,
        Prevent_NonDelivery_Report,
        Priority,
        Privicon,
        ProfileObject,
        Protocol,
        Protocol_Info,
        Protocol_Query,
        Protocol_Request,
        Proxy_Authenticate,
        Proxy_Authentication_Info,
        Proxy_Authorization,
        Proxy_Connection,
        Proxy_Features,
        Proxy_Instruction,
        Public,
        Public_Key_Pins,
        Public_Key_Pins_Report_Only,
        Range,
        Received,
        Received_SPF,
        Redirect_Ref,
        References,
        Referrer,
        Referrer_Root,
        Relay_Version,
        Reply_By,
        Reply_To,
        Require_Recipient_Valid_Since,
        Resent_Bcc,
        Resent_Cc,
        Resent_Date,
        Resent_From,
        Resent_Message_ID,
        Resent_Reply_To,
        Resent_Sender,
        Resent_To,
        Resolution_Hint,
        Resolver_Location,
        Retry_After,
        Return_Path,
        Safe,
        Schedule_Reply,
        Schedule_Tag,
        Sec_WebSocket_Accept,
        Sec_WebSocket_Extensions,
        Sec_WebSocket_Key,
        Sec_WebSocket_Protocol,
        Sec_WebSocket_Version,
        Security_Scheme,
        See_Also,
        Sender,
        Sensitivity,
        Server,
        Set_Cookie,
        Set_Cookie2,
        SetProfile,
        SIO_Label,
        SIO_Label_History,
        SLUG,
        SoapAction,
        Solicitation,
        Status_URI,
        Strict_Transport_Security,
        Subject,
        SubOK,
        Subst,
        Summary,
        Supersedes,
        Surrogate_Capability,
        Surrogate_Control,
        TCN,
        TE,
        Timeout,
        Title,
        To,
        Topic,
        Trailer,
        Transfer_Encoding,
        TTL,
        UA_Color,
        UA_Media,
        UA_Pixels,
        UA_Resolution,
        UA_Windowpixels,
        Upgrade,
        Urgency,
        URI,
        User_Agent,
        Variant_Vary,
        Vary,
        VBR_Info,
        Version,
        Via,
        Want_Digest,
        Warning,
        WWW_Authenticate,
        X_Archived_At,
        X_Device_Accept,
        X_Device_Accept_Charset,
        X_Device_Accept_Encoding,
        X_Device_Accept_Language,
        X_Device_User_Agent,
        X_Frame_Options,
        X_Mittente,
        X_PGP_Sig,
        X_Ricevuta,
        X_Riferimento_Message_ID,
        X_TipoRicevuta,
        X_Trasporto,
        X_VerificaSicurezza,
        X400_Content_Identifier,
        X400_Content_Return,
        X400_Content_Type,
        X400_MTS_Identifier,
        X400_Originator,
        X400_Received,
        X400_Recipients,
        X400_Trace,
        Xref
    };

    namespace detail {
        struct field_table
        {
            using array_type = std::array<utility::str_ref, 353>;

            // Strings are converted to lowercase
            static uint32_t digest(const utility::str_ref& s)
            {
                uint32_t r = 0;
                size_t n = s.size();
                unsigned char const* p = reinterpret_cast<unsigned char const*>(s.data());
                while (n >= 4)
                {
                    uint32_t v;
                    memcpy(&v, p, 4);
                    r = r * 5 + (v | 0x20202020);
                    p += 4;
                    n -= 4;
                }
                while (n > 0)
                {
                    r = r * 5 + (*p | 0x20);
                    ++p;
                    --n;
                }
                return r;
            }

            // This comparison is case-insensitive, and the
            // strings must contain only valid http field characters.
            static bool equals(const utility::str_ref& lhs, const utility::str_ref& rhs)
            {
                using Int = uint32_t; // or size_t
                auto n = lhs.size();
                if (n != rhs.size())
                    return false;
                auto p1 = lhs.data();
                auto p2 = rhs.data();
                auto constexpr S = sizeof(Int);
                auto constexpr Mask = static_cast<Int>(
                    0xDFDFDFDFDFDFDFDF & ~Int{ 0 });
                for (; n >= S; p1 += S, p2 += S, n -= S)
                {
                    Int v1, v2;
                    memcpy(&v1, p1, S);
                    memcpy(&v2, p2, S);
                    if ((v1 ^ v2) & Mask)
                        return false;
                }
                for (; n; ++p1, ++p2, --n)
                    if ((*p1 ^ *p2) & 0xDF)
                        return false;
                return true;
            }

            array_type by_name_;

            enum { N = 5155 };
            unsigned char map_[N][2] = {};

            /*
                From:
                https://www.iana.org/assignments/message-headers/message-headers.xhtml
            */
            field_table()
                : by_name_({ {
                    "<unknown-field>",
                    "A-IM",
                    "Accept",
                    "Accept-Additions",
                    "Accept-Charset",
                    "Accept-Datetime",
                    "Accept-Encoding",
                    "Accept-Features",
                    "Accept-Language",
                    "Accept-Patch",
                    "Accept-Post",
                    "Accept-Ranges",
                    "Access-Control",
                    "Access-Control-Allow-Credentials",
                    "Access-Control-Allow-Headers",
                    "Access-Control-Allow-Methods",
                    "Access-Control-Allow-Origin",
                    "Access-Control-Expose-Headers",
                    "Access-Control-Max-Age",
                    "Access-Control-Request-Headers",
                    "Access-Control-Request-Method",
                    "Age",
                    "Allow",
                    "ALPN",
                    "Also-Control",
                    "Alt-Svc",
                    "Alt-Used",
                    "Alternate-Recipient",
                    "Alternates",
                    "Apparently-To",
                    "Apply-To-Redirect-Ref",
                    "Approved",
                    "Archive",
                    "Archived-At",
                    "Article-Names",
                    "Article-Updates",
                    "Authentication-Control",
                    "Authentication-Info",
                    "Authentication-Results",
                    "Authorization",
                    "Auto-Submitted",
                    "Autoforwarded",
                    "Autosubmitted",
                    "Base",
                    "Bcc",
                    "Body",
                    "C-Ext",
                    "C-Man",
                    "C-Opt",
                    "C-PEP",
                    "C-PEP-Info",
                    "Cache-Control",
                    "CalDAV-Timezones",
                    "Cancel-Key",
                    "Cancel-Lock",
                    "Cc",
                    "Close",
                    "Comments",
                    "Compliance",
                    "Connection",
                    "Content-Alternative",
                    "Content-Base",
                    "Content-Description",
                    "Content-Disposition",
                    "Content-Duration",
                    "Content-Encoding",
                    "Content-features",
                    "Content-ID",
                    "Content-Identifier",
                    "Content-Language",
                    "Content-Length",
                    "Content-Location",
                    "Content-MD5",
                    "Content-Range",
                    "Content-Return",
                    "Content-Script-Type",
                    "Content-Style-Type",
                    "Content-Transfer-Encoding",
                    "Content-Type",
                    "Content-Version",
                    "Control",
                    "Conversion",
                    "Conversion-With-Loss",
                    "Cookie",
                    "Cookie2",
                    "Cost",
                    "DASL",
                    "Date",
                    "Date-Received",
                    "DAV",
                    "Default-Style",
                    "Deferred-Delivery",
                    "Delivery-Date",
                    "Delta-Base",
                    "Depth",
                    "Derived-From",
                    "Destination",
                    "Differential-ID",
                    "Digest",
                    "Discarded-X400-IPMS-Extensions",
                    "Discarded-X400-MTS-Extensions",
                    "Disclose-Recipients",
                    "Disposition-Notification-Options",
                    "Disposition-Notification-To",
                    "Distribution",
                    "DKIM-Signature",
                    "DL-Expansion-History",
                    "Downgraded-Bcc",
                    "Downgraded-Cc",
                    "Downgraded-Disposition-Notification-To",
                    "Downgraded-Final-Recipient",
                    "Downgraded-From",
                    "Downgraded-In-Reply-To",
                    "Downgraded-Mail-From",
                    "Downgraded-Message-Id",
                    "Downgraded-Original-Recipient",
                    "Downgraded-Rcpt-To",
                    "Downgraded-References",
                    "Downgraded-Reply-To",
                    "Downgraded-Resent-Bcc",
                    "Downgraded-Resent-Cc",
                    "Downgraded-Resent-From",
                    "Downgraded-Resent-Reply-To",
                    "Downgraded-Resent-Sender",
                    "Downgraded-Resent-To",
                    "Downgraded-Return-Path",
                    "Downgraded-Sender",
                    "Downgraded-To",
                    "EDIINT-Features",
                    "Eesst-Version",
                    "Encoding",
                    "Encrypted",
                    "Errors-To",
                    "ETag",
                    "Expect",
                    "Expires",
                    "Expiry-Date",
                    "Ext",
                    "Followup-To",
                    "Forwarded",
                    "From",
                    "Generate-Delivery-Report",
                    "GetProfile",
                    "Hobareg",
                    "Host",
                    "HTTP2-Settings",
                    "If",
                    "If-Match",
                    "If-Modified-Since",
                    "If-None-Match",
                    "If-Range",
                    "If-Schedule-Tag-Match",
                    "If-Unmodified-Since",
                    "IM",
                    "Importance",
                    "In-Reply-To",
                    "Incomplete-Copy",
                    "Injection-Date",
                    "Injection-Info",
                    "Jabber-ID",
                    "Keep-Alive",
                    "Keywords",
                    "Label",
                    "Language",
                    "Last-Modified",
                    "Latest-Delivery-Time",
                    "Lines",
                    "Link",
                    "List-Archive",
                    "List-Help",
                    "List-ID",
                    "List-Owner",
                    "List-Post",
                    "List-Subscribe",
                    "List-Unsubscribe",
                    "List-Unsubscribe-Post",
                    "Location",
                    "Lock-Token",
                    "Man",
                    "Max-Forwards",
                    "Memento-Datetime",
                    "Message-Context",
                    "Message-ID",
                    "Message-Type",
                    "Meter",
                    "Method-Check",
                    "Method-Check-Expires",
                    "MIME-Version",
                    "MMHS-Acp127-Message-Identifier",
                    "MMHS-Authorizing-Users",
                    "MMHS-Codress-Message-Indicator",
                    "MMHS-Copy-Precedence",
                    "MMHS-Exempted-Address",
                    "MMHS-Extended-Authorisation-Info",
                    "MMHS-Handling-Instructions",
                    "MMHS-Message-Instructions",
                    "MMHS-Message-Type",
                    "MMHS-Originator-PLAD",
                    "MMHS-Originator-Reference",
                    "MMHS-Other-Recipients-Indicator-CC",
                    "MMHS-Other-Recipients-Indicator-To",
                    "MMHS-Primary-Precedence",
                    "MMHS-Subject-Indicator-Codes",
                    "MT-Priority",
                    "Negotiate",
                    "Newsgroups",
                    "NNTP-Posting-Date",
                    "NNTP-Posting-Host",
                    "Non-Compliance",
                    "Obsoletes",
                    "Opt",
                    "Optional",
                    "Optional-WWW-Authenticate",
                    "Ordering-Type",
                    "Organization",
                    "Origin",
                    "Original-Encoded-Information-Types",
                    "Original-From",
                    "Original-Message-ID",
                    "Original-Recipient",
                    "Original-Sender",
                    "Original-Subject",
                    "Originator-Return-Address",
                    "Overwrite",
                    "P3P",
                    "Path",
                    "PEP",
                    "Pep-Info",
                    "PICS-Label",
                    "Position",
                    "Posting-Version",
                    "Pragma",
                    "Prefer",
                    "Preference-Applied",
                    "Prevent-NonDelivery-Report",
                    "Priority",
                    "Privicon",
                    "ProfileObject",
                    "Protocol",
                    "Protocol-Info",
                    "Protocol-Query",
                    "Protocol-Request",
                    "Proxy-Authenticate",
                    "Proxy-Authentication-Info",
                    "Proxy-Authorization",
                    "Proxy-Connection",
                    "Proxy-Features",
                    "Proxy-Instruction",
                    "Public",
                    "Public-Key-Pins",
                    "Public-Key-Pins-Report-Only",
                    "Range",
                    "Received",
                    "Received-SPF",
                    "Redirect-Ref",
                    "References",
                    "Referer",
                    "Referer-Root",
                    "Relay-Version",
                    "Reply-By",
                    "Reply-To",
                    "Require-Recipient-Valid-Since",
                    "Resent-Bcc",
                    "Resent-Cc",
                    "Resent-Date",
                    "Resent-From",
                    "Resent-Message-ID",
                    "Resent-Reply-To",
                    "Resent-Sender",
                    "Resent-To",
                    "Resolution-Hint",
                    "Resolver-Location",
                    "Retry-After",
                    "Return-Path",
                    "Safe",
                    "Schedule-Reply",
                    "Schedule-Tag",
                    "Sec-WebSocket-Accept",
                    "Sec-WebSocket-Extensions",
                    "Sec-WebSocket-Key",
                    "Sec-WebSocket-Protocol",
                    "Sec-WebSocket-Version",
                    "Security-Scheme",
                    "See-Also",
                    "Sender",
                    "Sensitivity",
                    "Server",
                    "Set-Cookie",
                    "Set-Cookie2",
                    "SetProfile",
                    "SIO-Label",
                    "SIO-Label-History",
                    "SLUG",
                    "SoapAction",
                    "Solicitation",
                    "Status-URI",
                    "Strict-Transport-Security",
                    "Subject",
                    "SubOK",
                    "Subst",
                    "Summary",
                    "Supersedes",
                    "Surrogate-Capability",
                    "Surrogate-Control",
                    "TCN",
                    "TE",
                    "Timeout",
                    "Title",
                    "To",
                    "Topic",
                    "Trailer",
                    "Transfer-Encoding",
                    "TTL",
                    "UA-Color",
                    "UA-Media",
                    "UA-Pixels",
                    "UA-Resolution",
                    "UA-Windowpixels",
                    "Upgrade",
                    "Urgency",
                    "URI",
                    "User-Agent",
                    "Variant-Vary",
                    "Vary",
                    "VBR-Info",
                    "Version",
                    "Via",
                    "Want-Digest",
                    "Warning",
                    "WWW-Authenticate",
                    "X-Archived-At",
                    "X-Device-Accept",
                    "X-Device-Accept-Charset",
                    "X-Device-Accept-Encoding",
                    "X-Device-Accept-Language",
                    "X-Device-User-Agent",
                    "X-Frame-Options",
                    "X-Mittente",
                    "X-PGP-Sig",
                    "X-Ricevuta",
                    "X-Riferimento-Message-ID",
                    "X-TipoRicevuta",
                    "X-Trasporto",
                    "X-VerificaSicurezza",
                    "X400-Content-Identifier",
                    "X400-Content-Return",
                    "X400-Content-Type",
                    "X400-MTS-Identifier",
                    "X400-Originator",
                    "X400-Received",
                    "X400-Recipients",
                    "X400-Trace",
                    "Xref"
                } })
            {
                for (size_t i = 1, n = 256; i < n; ++i)
                {
                    auto& sv = by_name_[i];
                    auto h = digest(sv);
                    auto j = h % N;
                    //assert(map_[j][0] == 0);
                    map_[j][0] = static_cast<unsigned char>(i);
                }

                for (size_t i = 256, n = by_name_.size(); i < n; ++i)
                {
                    auto& sv = by_name_[i];
                    auto h = digest(sv);
                    auto j = h % N;
                    //assert(map_[j][1] == 0);
                    map_[j][1] = static_cast<unsigned char>(i - 255);
                }
            }

            HTTPField string_to_field(const utility::str_ref& s) const
            {
                auto h = digest(s);
                auto j = h % N;
                int i = map_[j][0];
                const utility::str_ref* s2 = &by_name_[i];
                if (i != 0 && equals(s, *s2))
                    return static_cast<HTTPField>(i);
                i = map_[j][1];
                if (i == 0)
                    return HTTPField::Unknown;
                i += 255;
                s2 = &by_name_[i];

                if (equals(s, *s2))
                    return static_cast<HTTPField>(i);
                return HTTPField::Unknown;
            }

            array_type::const_iterator begin() const
            {
                return by_name_.begin();
            }
        };

        static inline field_table const& get_field_table()
        {
            static field_table const tab;
            return tab;
        }

        static inline const utility::str_ref& field_to_string(HTTPField f)
        {
            auto const& v = get_field_table();
            //assert(static_cast<unsigned>(f) < v.size());
            return v.begin()[static_cast<unsigned>(f)];
        }

    } // detail

    static inline const char *field_to_string(HTTPField f)
    {
        return detail::field_to_string(f).data();
    }

    static inline HTTPField string_to_field(const char *s)
    {
        return detail::get_field_table().string_to_field(s);
    }

    static inline HTTPField string_to_field(const std::string &s)
    {
        return detail::get_field_table().string_to_field(s);
    }
}

#ifndef CROW_MSVC_WORKAROUND
constexpr crow::HTTPMethod operator "" _method(const char* str, size_t /*len*/)
{
    return
        crow::black_magic::is_equ_p(str, "GET", 3) ? crow::HTTPMethod::Get :
        crow::black_magic::is_equ_p(str, "DELETE", 6) ? crow::HTTPMethod::Delete :
        crow::black_magic::is_equ_p(str, "HEAD", 4) ? crow::HTTPMethod::Head :
        crow::black_magic::is_equ_p(str, "POST", 4) ? crow::HTTPMethod::Post :
        crow::black_magic::is_equ_p(str, "PUT", 3) ? crow::HTTPMethod::Put :
        crow::black_magic::is_equ_p(str, "OPTIONS", 7) ? crow::HTTPMethod::Options :
        crow::black_magic::is_equ_p(str, "CONNECT", 7) ? crow::HTTPMethod::Connect :
        crow::black_magic::is_equ_p(str, "TRACE", 5) ? crow::HTTPMethod::Trace :
        crow::black_magic::is_equ_p(str, "PATCH", 5) ? crow::HTTPMethod::Patch :
        crow::black_magic::is_equ_p(str, "PURGE", 5) ? crow::HTTPMethod::Purge :
        throw std::runtime_error("invalid http method");
}
#endif

#ifndef CROW_CAN_USE_CPP14
namespace std
{
    template <> struct hash<crow::HTTPField>
    {
        size_t operator()(crow::HTTPField s) const
        {
            return hash<unsigned short>()(static_cast<unsigned short>(s));
        }
    };
}
#endif
