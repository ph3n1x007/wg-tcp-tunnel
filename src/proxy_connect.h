// wg-tcp-tunnel - proxy_connect.h
// SPDX-FileCopyrightText: 2025 Arkadiusz Bokowy and contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "proxy_auth.h"

namespace wg::proxy {

namespace asio = boost::asio;

// Configuration handed to udp2tcp to enable HTTP CONNECT mode. The
// auth_provider held by the connector is consumed across one handshake
// (SSPI security contexts cannot be reused), so we accept a factory and
// rebuild a fresh provider on each connect attempt.
struct config {
	asio::ip::tcp::endpoint endpoint;                          // resolved proxy address
	std::string target;                                        // "host:port" for CONNECT line
	std::function<std::unique_ptr<auth_provider>()> make_auth; // nullable: nullptr / returns nullptr = no auth
};

// Async HTTP CONNECT state machine. Call start() on a socket that has
// already been TCP-connected to the proxy. The connector sends CONNECT,
// loops through any Proxy-Authenticate / Proxy-Authorization rounds the
// auth provider produces, and invokes the completion handler with the
// final error_code:
//
//   - default-constructed (no error) on a successful 200 response,
//   - asio::error::access_denied if the proxy refused with a non-recoverable
//     auth status,
//   - asio::error::network_unreachable for non-407, non-200 responses,
//   - the asio error_code propagated from a transport failure otherwise.
//
// A single connector instance is reusable across reconnects: each start()
// resets the streambuf and round counter.
class connector {
public:
	using completion_t = std::function<void(const boost::system::error_code &)>;

	explicit connector(asio::ip::tcp::socket & socket) : m_socket(socket) {}

	auto start(std::string target, auth_provider * auth, completion_t completion) -> void;

private:
	auto do_send_request() -> void;
	auto on_request_sent(const boost::system::error_code & ec, std::size_t n) -> void;
	auto do_read_response() -> void;
	auto on_response(const boost::system::error_code & ec, std::size_t n) -> void;
	auto finish(const boost::system::error_code & ec) -> void;

	asio::ip::tcp::socket & m_socket;
	asio::streambuf m_response;
	std::string m_request;
	std::string m_target;          // host:port string for the CONNECT request line
	auth_provider * m_auth{ nullptr };
	std::string m_pending_token;   // empty for unauthenticated first request
	completion_t m_completion;
	int m_rounds{ 0 };

	static constexpr int max_rounds = 10;
	static constexpr std::size_t max_response_size = 8192;
};

} // namespace wg::proxy
