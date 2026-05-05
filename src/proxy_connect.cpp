// wg-tcp-tunnel - proxy_connect.cpp
// SPDX-FileCopyrightText: 2025 Arkadiusz Bokowy and contributors
// SPDX-License-Identifier: MIT

#include "proxy_connect.h"

#include <cctype>
#include <sstream>
#include <string_view>
#include <utility>

#include <boost/log/trivial.hpp>

namespace wg::proxy {

namespace {

#define LOG(lvl) BOOST_LOG_TRIVIAL(lvl) << "proxy::"

auto iequals(std::string_view a, std::string_view b) -> bool {
	if (a.size() != b.size())
		return false;
	for (std::size_t i = 0; i < a.size(); ++i)
		if (std::tolower(static_cast<unsigned char>(a[i])) !=
		    std::tolower(static_cast<unsigned char>(b[i])))
			return false;
	return true;
}

auto trim(std::string_view s) -> std::string_view {
	while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
		s.remove_prefix(1);
	while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
		s.remove_suffix(1);
	return s;
}

struct parsed_response {
	int status{ 0 };
	bool connection_close{ false };
	std::string our_scheme_token; // server's Proxy-Authenticate token for our scheme
	bool our_scheme_seen{ false };
};

auto parse_response(std::string_view raw, std::string_view our_scheme) -> parsed_response {
	parsed_response r;
	std::size_t pos = 0;
	std::size_t line_no = 0;
	while (pos < raw.size()) {
		auto eol = raw.find("\r\n", pos);
		if (eol == std::string_view::npos)
			break;
		auto line = raw.substr(pos, eol - pos);
		pos = eol + 2;
		if (line.empty())
			break; // end of headers
		if (line_no == 0) {
			// HTTP/1.x XXX message
			auto sp1 = line.find(' ');
			if (sp1 != std::string_view::npos) {
				auto rest = line.substr(sp1 + 1);
				auto sp2 = rest.find(' ');
				auto code_str = rest.substr(0, sp2);
				try {
					r.status = std::stoi(std::string(code_str));
				} catch (...) {
					r.status = 0;
				}
			}
		} else {
			auto colon = line.find(':');
			if (colon == std::string_view::npos) {
				++line_no;
				continue;
			}
			auto name = trim(line.substr(0, colon));
			auto value = trim(line.substr(colon + 1));
			if (iequals(name, "Connection") && iequals(value, "close"))
				r.connection_close = true;
			if (iequals(name, "Proxy-Authenticate")) {
				// "Negotiate <token>" or just "Negotiate" or "Basic realm=..."
				auto sp = value.find(' ');
				auto scheme_part = (sp == std::string_view::npos) ? value : value.substr(0, sp);
				if (iequals(scheme_part, our_scheme)) {
					r.our_scheme_seen = true;
					if (sp != std::string_view::npos) {
						auto tok = trim(value.substr(sp + 1));
						// Strip a leading "realm=..." style param for Basic;
						// for NTLM/Negotiate the rest is the base64 token.
						if (!iequals(our_scheme, "Basic"))
							r.our_scheme_token = std::string(tok);
					}
				}
			}
		}
		++line_no;
	}
	return r;
}

} // anonymous namespace

auto connector::start(std::string target, auth_provider * auth, completion_t completion) -> void {
	m_target = std::move(target);
	m_auth = auth;
	m_completion = std::move(completion);
	m_rounds = 0;
	m_pending_token.clear();
	m_response.consume(m_response.size());

	// If an auth provider was supplied, ask it for the first token now so we
	// avoid the round trip the proxy would otherwise force with a 407.
	if (m_auth != nullptr) {
		auto tok = m_auth->next_token({});
		if (!tok) {
			LOG(error) << "auth provider produced no initial token";
			finish(boost::asio::error::access_denied);
			return;
		}
		m_pending_token = std::move(*tok);
	}

	do_send_request();
}

auto connector::do_send_request() -> void {
	std::ostringstream req;
	req << "CONNECT " << m_target << " HTTP/1.1\r\n"
	    << "Host: " << m_target << "\r\n"
	    << "Proxy-Connection: Keep-Alive\r\n"
	    << "User-Agent: wg-tcp-tunnel/1\r\n";
	if (m_auth != nullptr && !m_pending_token.empty())
		req << "Proxy-Authorization: " << m_auth->scheme() << ' ' << m_pending_token << "\r\n";
	req << "\r\n";
	m_request = req.str();

	LOG(debug) << "sending CONNECT to " << m_target
	           << (m_pending_token.empty() ? " (no auth)" : " (with auth token)");

	asio::async_write(
	    m_socket, asio::buffer(m_request),
	    [this](const auto & ec, std::size_t n) { on_request_sent(ec, n); });
}

auto connector::on_request_sent(const boost::system::error_code & ec, std::size_t) -> void {
	if (ec) {
		LOG(error) << "CONNECT write failed: " << ec.message();
		finish(ec);
		return;
	}
	do_read_response();
}

auto connector::do_read_response() -> void {
	m_response.consume(m_response.size());
	asio::async_read_until(
	    m_socket, m_response, "\r\n\r\n",
	    [this](const auto & ec, std::size_t n) { on_response(ec, n); });
}

auto connector::on_response(const boost::system::error_code & ec, std::size_t n) -> void {
	if (ec) {
		LOG(error) << "CONNECT read failed: " << ec.message();
		finish(ec);
		return;
	}
	if (n > max_response_size) {
		LOG(error) << "CONNECT response too large: " << n;
		finish(boost::asio::error::message_size);
		return;
	}

	// Snapshot exactly the response headers, preserving any tunnel bytes that
	// async_read_until may have buffered past the terminator. Boost.Asio's
	// streambuf consume() drops bytes from the input sequence, so anything we
	// don't consume here remains queued for the first tunnel read.
	std::string headers(asio::buffers_begin(m_response.data()),
	                    asio::buffers_begin(m_response.data()) + n);
	m_response.consume(n);

	const std::string scheme = (m_auth != nullptr) ? m_auth->scheme() : std::string();
	auto parsed = parse_response(headers, scheme);

	LOG(debug) << "proxy responded status=" << parsed.status;

	if (parsed.status == 200) {
		// Tunnel established. If the proxy sent extra bytes past the headers
		// (rare, but legal), they belong to the tunnel — splice them onto the
		// front of whatever the next read consumer expects. The udp2tcp's
		// raw-mode header read uses async_read on the same socket, which
		// will not see streambuf-buffered bytes; so any leftover here is a
		// protocol violation by the proxy and we treat it as fatal.
		if (m_response.size() != 0) {
			LOG(error) << "proxy sent " << m_response.size()
			           << " unexpected bytes after CONNECT 200";
			finish(boost::asio::error::network_unreachable);
			return;
		}
		finish({});
		return;
	}

	if (parsed.status != 407) {
		LOG(error) << "proxy refused CONNECT with status " << parsed.status;
		finish(boost::asio::error::network_unreachable);
		return;
	}

	// 407 Proxy Authentication Required — try another round.
	if (m_auth == nullptr) {
		LOG(error) << "proxy requires auth but none configured (use --proxy-auth)";
		finish(boost::asio::error::access_denied);
		return;
	}
	if (parsed.connection_close) {
		LOG(error) << "proxy closed connection mid-handshake; cannot continue stateful auth";
		finish(boost::asio::error::access_denied);
		return;
	}
	if (++m_rounds >= max_rounds) {
		LOG(error) << "proxy auth exceeded max rounds";
		finish(boost::asio::error::access_denied);
		return;
	}
	if (!parsed.our_scheme_seen) {
		LOG(error) << "proxy does not offer our auth scheme: " << scheme;
		finish(boost::asio::error::access_denied);
		return;
	}

	auto tok = m_auth->next_token(parsed.our_scheme_token);
	if (!tok) {
		LOG(error) << "auth provider exhausted; proxy still rejecting";
		finish(boost::asio::error::access_denied);
		return;
	}
	m_pending_token = std::move(*tok);
	do_send_request();
}

auto connector::finish(const boost::system::error_code & ec) -> void {
	auto cb = std::move(m_completion);
	m_completion = {};
	if (cb)
		cb(ec);
}

} // namespace wg::proxy
