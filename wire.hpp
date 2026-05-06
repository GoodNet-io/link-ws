// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/wire.hpp
/// @brief  RFC 6455 frame layout helpers + the SHA-1 / base64 pair
///         the upgrade handshake needs.
///
/// SHA-1 is defined here despite being broken for general
/// cryptographic use because RFC 6455 §1.3 hard-codes it for the
/// `Sec-WebSocket-Accept` derivation. The accept hash is a
/// connection-level handshake check, not a security primitive — the
/// kernel's identity layer (Noise XX/IK) lives above the WS
/// transport and provides the actual authentication.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gn::link::ws::wire {

/* ── SHA-1 (RFC 3174) — 160-bit digest ──────────────────────────── */

struct Sha1Ctx {
    std::uint32_t h[5];
    std::uint64_t length;
    std::array<std::uint8_t, 64> buffer;
    std::size_t buffer_used;
};

inline void sha1_init(Sha1Ctx& c) noexcept {
    c.h[0] = 0x67452301u;
    c.h[1] = 0xEFCDAB89u;
    c.h[2] = 0x98BADCFEu;
    c.h[3] = 0x10325476u;
    c.h[4] = 0xC3D2E1F0u;
    c.length      = 0;
    c.buffer_used = 0;
}

inline std::uint32_t rotl32(std::uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

inline void sha1_block(Sha1Ctx& c, const std::uint8_t* block) noexcept {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) <<  8) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    auto a = c.h[0]; auto b = c.h[1]; auto cc = c.h[2];
    auto d = c.h[3]; auto e = c.h[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f, k;
        if (i < 20)      { f = (b & cc) | (~b & d);   k = 0x5A827999u; }
        else if (i < 40) { f = b ^ cc ^ d;            k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ cc ^ d;            k = 0xCA62C1D6u; }
        std::uint32_t t = rotl32(a, 5) + f + e + k + w[i];
        e  = d; d  = cc; cc = rotl32(b, 30); b  = a; a  = t;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e;
}

inline void sha1_update(Sha1Ctx& c, const std::uint8_t* data, std::size_t n) noexcept {
    c.length += n;
    while (n > 0) {
        const std::size_t take = std::min<std::size_t>(64 - c.buffer_used, n);
        std::memcpy(c.buffer.data() + c.buffer_used, data, take);
        c.buffer_used += take;
        data += take;
        n -= take;
        if (c.buffer_used == 64) {
            sha1_block(c, c.buffer.data());
            c.buffer_used = 0;
        }
    }
}

inline std::array<std::uint8_t, 20> sha1_final(Sha1Ctx& c) noexcept {
    const std::uint64_t bit_len = c.length * 8;
    /// Append 0x80, pad with zeros to leave 8 bytes for the BE bit
    /// length, write the length, and run a final block.
    c.buffer[c.buffer_used++] = 0x80;
    if (c.buffer_used > 56) {
        while (c.buffer_used < 64) c.buffer[c.buffer_used++] = 0;
        sha1_block(c, c.buffer.data());
        c.buffer_used = 0;
    }
    while (c.buffer_used < 56) c.buffer[c.buffer_used++] = 0;
    for (int i = 7; i >= 0; --i) {
        c.buffer[c.buffer_used++] =
            static_cast<std::uint8_t>(bit_len >> (i * 8));
    }
    sha1_block(c, c.buffer.data());

    std::array<std::uint8_t, 20> out{};
    for (std::size_t i = 0; i < 5; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>(c.h[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(c.h[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(c.h[i] >>  8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(c.h[i]);
    }
    return out;
}

inline std::array<std::uint8_t, 20> sha1(std::string_view in) noexcept {
    Sha1Ctx c{};
    sha1_init(c);
    sha1_update(c,
        reinterpret_cast<const std::uint8_t*>(in.data()), in.size());
    return sha1_final(c);
}

/* ── Base64 (RFC 4648 §4) ───────────────────────────────────────── */

inline std::string base64_encode(std::span<const std::uint8_t> in) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= in.size()) {
        const auto a = in[i++], b = in[i++], c = in[i++];
        const std::uint32_t v =
            (static_cast<std::uint32_t>(a) << 16U) |
            (static_cast<std::uint32_t>(b) <<  8U) |
             static_cast<std::uint32_t>(c);
        out += kAlphabet[(v >> 18U) & 0x3fU];
        out += kAlphabet[(v >> 12U) & 0x3fU];
        out += kAlphabet[(v >>  6U) & 0x3fU];
        out += kAlphabet[(v >>  0U) & 0x3fU];
    }
    if (i < in.size()) {
        const auto a = in[i++];
        std::uint32_t v = static_cast<std::uint32_t>(a) << 16U;
        const bool have_second = i < in.size();
        if (have_second) {
            v |= static_cast<std::uint32_t>(in[i++]) << 8U;
        }
        out += kAlphabet[(v >> 18U) & 0x3fU];
        out += kAlphabet[(v >> 12U) & 0x3fU];
        if (have_second) {
            out += kAlphabet[(v >> 6U) & 0x3fU];
            out += '=';
        } else {
            out += "==";
        }
    }
    return out;
}

/* ── Frame layout (RFC 6455 §5) ─────────────────────────────────── */

/// Magic GUID from RFC 6455 §1.3. Concatenated with the client's
/// `Sec-WebSocket-Key` and SHA-1+base64-d to form the server's
/// `Sec-WebSocket-Accept` reply.
inline constexpr std::string_view kHandshakeMagic =
    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` value the server returns in
/// response to a client's `Sec-WebSocket-Key` per RFC 6455 §1.3.
inline std::string handshake_accept(std::string_view key) {
    std::string concat;
    concat.reserve(key.size() + kHandshakeMagic.size());
    concat += key;
    concat += kHandshakeMagic;
    const auto digest = sha1(concat);
    return base64_encode(
        std::span<const std::uint8_t>(digest.data(), digest.size()));
}

/// Frame header produced by `parse_frame_header`.
struct FrameHeader {
    bool          fin    = false;
    std::uint8_t  opcode = 0;
    bool          masked = false;
    std::uint64_t payload_len = 0;
    std::uint8_t  mask[4]{};
    std::size_t   header_size = 0;  ///< bytes consumed in `bytes`
};

/// Parse a WebSocket frame header out of @p bytes. Returns
/// `nullopt` when the buffer is too short for the full header — the
/// caller reads more bytes and retries. Sets `header_size` on
/// success so the caller knows where the payload starts.
inline std::optional<FrameHeader> parse_frame_header(
    std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 2) return std::nullopt;
    FrameHeader h{};
    h.fin    = (bytes[0] & 0x80u) != 0;
    h.opcode =  bytes[0] & 0x0fu;
    h.masked = (bytes[1] & 0x80u) != 0;
    const std::uint8_t len_field = bytes[1] & 0x7fu;
    std::size_t cursor = 2;

    if (len_field < 126) {
        h.payload_len = len_field;
    } else if (len_field == 126) {
        if (bytes.size() < cursor + 2) return std::nullopt;
        h.payload_len =
            (static_cast<std::uint64_t>(bytes[cursor]) << 8) |
             static_cast<std::uint64_t>(bytes[cursor + 1]);
        cursor += 2;
    } else {  // 127
        if (bytes.size() < cursor + 8) return std::nullopt;
        h.payload_len = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            h.payload_len = (h.payload_len << 8U) |
                            static_cast<std::uint64_t>(bytes[cursor + i]);
        }
        cursor += 8;
    }

    if (h.masked) {
        if (bytes.size() < cursor + 4) return std::nullopt;
        std::memcpy(h.mask, &bytes[cursor], 4);
        cursor += 4;
    }
    h.header_size = cursor;
    return h;
}

/// XOR a payload buffer in place with the 4-byte WebSocket mask.
/// Tolerates an empty buffer; mask index wraps modulo 4 per RFC.
inline void apply_mask(std::span<std::uint8_t> payload,
                       const std::uint8_t (&mask)[4]) noexcept {
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] ^= mask[i & 3u];
    }
}

/// Build a binary frame (FIN=1, opcode=0x2). When @p mask is true
/// (client-to-server), generate a fresh mask and apply it; the
/// `mask_seed` parameter is used as the masking key (caller seeds
/// with random or another source — masking is correctness, not a
/// security primitive).
inline std::vector<std::uint8_t> build_binary_frame(
    std::span<const std::uint8_t> payload,
    bool mask,
    std::uint32_t mask_seed) {
    /// Header layout: 1 opcode byte + length (1, 3 or 9 bytes) +
    /// optional 4-byte mask. Pre-sizing the destination buffer to the
    /// exact total avoids any realloc on the write path and lets the
    /// optimiser treat the writes as straight stores.
    const std::size_t length_bytes =
        payload.size() < 126U        ? std::size_t{1}
        : payload.size() <= 0xffffU  ? std::size_t{3}
                                     : std::size_t{9};
    const std::size_t mask_bytes  = mask ? std::size_t{4} : std::size_t{0};
    const std::size_t header_size = 1U + length_bytes + mask_bytes;
    const std::size_t total       = header_size + payload.size();

    std::vector<std::uint8_t> out(total);

    out[0] = static_cast<std::uint8_t>(0x80U | 0x02U);  // FIN | binary

    const std::uint8_t mask_bit =
        mask ? static_cast<std::uint8_t>(0x80U) : std::uint8_t{0};
    std::size_t cursor = 1;
    if (payload.size() < 126U) {
        out[cursor++] = static_cast<std::uint8_t>(
            mask_bit | static_cast<std::uint8_t>(payload.size()));
    } else if (payload.size() <= 0xffffU) {
        out[cursor++] = static_cast<std::uint8_t>(mask_bit | 126U);
        out[cursor++] = static_cast<std::uint8_t>(payload.size() >> 8U);
        out[cursor++] = static_cast<std::uint8_t>(payload.size());
    } else {
        out[cursor++] = static_cast<std::uint8_t>(mask_bit | 127U);
        const std::uint64_t n = payload.size();
        for (int shift = 56; shift >= 0; shift -= 8) {
            out[cursor++] = static_cast<std::uint8_t>(n >> shift);
        }
    }

    if (mask) {
        const std::uint8_t mk[4] = {
            static_cast<std::uint8_t>(mask_seed >> 24),
            static_cast<std::uint8_t>(mask_seed >> 16),
            static_cast<std::uint8_t>(mask_seed >>  8),
            static_cast<std::uint8_t>(mask_seed),
        };
        out[cursor++] = mk[0];
        out[cursor++] = mk[1];
        out[cursor++] = mk[2];
        out[cursor++] = mk[3];
        for (std::size_t i = 0; i < payload.size(); ++i) {
            out[cursor + i] =
                static_cast<std::uint8_t>(payload[i] ^ mk[i & 3u]);
        }
    } else if (!payload.empty()) {
        std::memcpy(out.data() + cursor, payload.data(), payload.size());
    }
    return out;
}

/// Build an unmasked close frame with no payload (RFC 6455 §5.5.1).
inline std::vector<std::uint8_t> build_close_frame(bool mask,
                                                    std::uint32_t mask_seed) {
    std::vector<std::uint8_t> out{static_cast<std::uint8_t>(0x80U | 0x08U)};
    out.push_back(mask ? static_cast<std::uint8_t>(0x80U) : std::uint8_t{0});
    if (mask) {
        out.push_back(static_cast<std::uint8_t>(mask_seed >> 24));
        out.push_back(static_cast<std::uint8_t>(mask_seed >> 16));
        out.push_back(static_cast<std::uint8_t>(mask_seed >>  8));
        out.push_back(static_cast<std::uint8_t>(mask_seed));
    }
    return out;
}

/// Build a pong frame echoing @p payload (RFC 6455 §5.5.3 mandates
/// servers respond to ping with pong carrying the same data).
inline std::vector<std::uint8_t> build_pong_frame(
    std::span<const std::uint8_t> payload,
    bool mask,
    std::uint32_t mask_seed) {
    /// Pong is the same shape as a binary frame but with opcode 0xA.
    auto out = build_binary_frame(payload, mask, mask_seed);
    out[0] = static_cast<std::uint8_t>(0x80U | 0x0AU);
    return out;
}

/// Build a ping frame carrying @p payload (RFC 6455 §5.5.2).
/// Production code does not emit pings — the helper exists so the
/// regression suite for `backpressure.md` §3.1 can simulate a
/// peer-initiated ping flood on the receive path.
inline std::vector<std::uint8_t> build_ping_frame(
    std::span<const std::uint8_t> payload,
    bool mask,
    std::uint32_t mask_seed) {
    /// Ping shares the binary-frame shape but with opcode 0x9.
    auto out = build_binary_frame(payload, mask, mask_seed);
    out[0] = static_cast<std::uint8_t>(0x80U | 0x09U);
    return out;
}

} // namespace gn::link::ws::wire
