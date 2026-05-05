// wg-tcp-tunnel - proxy_auth_basic.cpp
// SPDX-FileCopyrightText: 2025 Arkadiusz Bokowy and contributors
// SPDX-License-Identifier: MIT

#include "proxy_auth.h"

#include <cstdint>
#include <stdexcept>

namespace wg::proxy {

namespace {

constexpr char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr int b64_value(char c) {
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

class basic_provider : public auth_provider {
public:
	explicit basic_provider(std::string user_pass) : m_token(base64_encode(user_pass)) {}

	[[nodiscard]] auto scheme() const -> std::string override { return "Basic"; }

	auto next_token(std::string_view) -> std::optional<std::string> override {
		if (m_done)
			return std::nullopt;
		m_done = true;
		return m_token;
	}

private:
	std::string m_token;
	bool m_done{ false };
};

} // anonymous namespace

auto base64_encode(std::string_view data) -> std::string {
	std::string out;
	out.reserve(((data.size() + 2) / 3) * 4);

	auto p = reinterpret_cast<const uint8_t *>(data.data());
	auto n = data.size();
	size_t i = 0;
	for (; i + 3 <= n; i += 3) {
		uint32_t v = (uint32_t(p[i]) << 16) | (uint32_t(p[i + 1]) << 8) | uint32_t(p[i + 2]);
		out.push_back(b64_alphabet[(v >> 18) & 0x3F]);
		out.push_back(b64_alphabet[(v >> 12) & 0x3F]);
		out.push_back(b64_alphabet[(v >> 6) & 0x3F]);
		out.push_back(b64_alphabet[v & 0x3F]);
	}
	if (i < n) {
		uint32_t v = uint32_t(p[i]) << 16;
		if (i + 1 < n)
			v |= uint32_t(p[i + 1]) << 8;
		out.push_back(b64_alphabet[(v >> 18) & 0x3F]);
		out.push_back(b64_alphabet[(v >> 12) & 0x3F]);
		out.push_back((i + 1 < n) ? b64_alphabet[(v >> 6) & 0x3F] : '=');
		out.push_back('=');
	}
	return out;
}

auto base64_decode(std::string_view data) -> std::string {
	std::string out;
	out.reserve((data.size() / 4) * 3);

	int buf = 0;
	int bits = 0;
	for (char c : data) {
		if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t')
			continue;
		int v = b64_value(c);
		if (v < 0)
			throw std::runtime_error("Invalid base64 input");
		buf = (buf << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(static_cast<char>((buf >> bits) & 0xFF));
		}
	}
	return out;
}

auto make_basic_provider(std::string user_pass) -> std::unique_ptr<auth_provider> {
	return std::make_unique<basic_provider>(std::move(user_pass));
}

} // namespace wg::proxy
