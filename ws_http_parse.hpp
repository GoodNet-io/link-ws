// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws_http_parse.hpp
/// @brief  RFC 7230 HTTP/1.1 request / response header line parser
///         used by the WebSocket upgrade handshake. Split out of
///         ws.cpp so the framing pipeline and the HTTP-1.1 parsing
///         pipeline can evolve independently — the parsing surface
///         is small but exercised by every WS / WSS
///         session and is the natural seam between handshake-phase
///         and frame-phase code in `WsLink::Session`.
///
/// Header-only (small + only used by the WS plugin's TU); no separate
/// .cpp. Both `parse_http_request` and `parse_http_response` are
/// `inline` so the kernel-mode bundled build and the standalone
/// plugin build share one translation unit's worth of code without
/// linker duplicates.

#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace gn::link::ws {

inline std::string_view trim_lws(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

struct ParsedRequest {
    std::string method;
    std::string target;
    std::unordered_map<std::string, std::string> headers;
};

inline std::optional<ParsedRequest>
parse_http_request(std::string_view raw) {
    /// Walk the buffer line by line, consuming up to "\r\n\r\n".
    /// The minimum a valid WS upgrade carries is request-line +
    /// `Host:` + `Upgrade: websocket` + `Connection: Upgrade` +
    /// `Sec-WebSocket-Key:` + `Sec-WebSocket-Version: 13`. We
    /// accept any header order.
    ParsedRequest pr;
    std::size_t pos = 0;
    auto next_line = [&]() -> std::optional<std::string_view> {
        const auto crlf = raw.find("\r\n", pos);
        if (crlf == std::string_view::npos) return std::nullopt;
        const auto line = raw.substr(pos, crlf - pos);
        pos = crlf + 2;
        return line;
    };

    auto request_line = next_line();
    if (!request_line) return std::nullopt;
    auto sp1 = request_line->find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    auto sp2 = request_line->find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return std::nullopt;
    pr.method = std::string{request_line->substr(0, sp1)};
    pr.target = std::string{request_line->substr(sp1 + 1, sp2 - sp1 - 1)};

    while (true) {
        auto line = next_line();
        if (!line) return std::nullopt;
        if (line->empty()) break;
        const auto colon = line->find(':');
        if (colon == std::string_view::npos) continue;
        std::string name{trim_lws(line->substr(0, colon))};
        std::string value{trim_lws(line->substr(colon + 1))};
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char ch) { return std::tolower(ch); });
        pr.headers[std::move(name)] = std::move(value);
    }
    return pr;
}

struct ParsedResponse {
    int status = 0;
    std::unordered_map<std::string, std::string> headers;
};

inline std::optional<ParsedResponse>
parse_http_response(std::string_view raw) {
    ParsedResponse pr;
    std::size_t pos = 0;
    auto next_line = [&]() -> std::optional<std::string_view> {
        const auto crlf = raw.find("\r\n", pos);
        if (crlf == std::string_view::npos) return std::nullopt;
        const auto line = raw.substr(pos, crlf - pos);
        pos = crlf + 2;
        return line;
    };

    auto status_line = next_line();
    if (!status_line) return std::nullopt;
    /// "HTTP/1.1 101 Switching Protocols"
    auto sp1 = status_line->find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    auto sp2 = status_line->find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return std::nullopt;
    const auto code_sv = status_line->substr(sp1 + 1, sp2 - sp1 - 1);
    pr.status = 0;
    for (auto ch : code_sv) {
        if (ch < '0' || ch > '9') return std::nullopt;
        pr.status = pr.status * 10 + (ch - '0');
    }

    while (true) {
        auto line = next_line();
        if (!line) return std::nullopt;
        if (line->empty()) break;
        const auto colon = line->find(':');
        if (colon == std::string_view::npos) continue;
        std::string name{trim_lws(line->substr(0, colon))};
        std::string value{trim_lws(line->substr(colon + 1))};
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char ch) { return std::tolower(ch); });
        pr.headers[std::move(name)] = std::move(value);
    }
    return pr;
}

}  // namespace gn::link::ws
