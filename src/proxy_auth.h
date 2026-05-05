// wg-tcp-tunnel - proxy_auth.h
// SPDX-FileCopyrightText: 2025 Arkadiusz Bokowy and contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace wg::proxy {

// Auth providers produce successive base64-encoded tokens for the
// `Proxy-Authorization: <scheme> <token>` header during HTTP CONNECT.
//
// Single-round schemes (Basic) ignore the server token and return a final
// token on first call. Multi-round schemes (NTLM, Negotiate) consume the
// server's challenge token from the previous 407 response and return the
// next client token. All tokens crossing this interface are already
// base64-encoded; the connector concatenates them with the scheme name.
class auth_provider {
public:
	virtual ~auth_provider() = default;

	// HTTP auth scheme name. Must match what the proxy advertises in
	// Proxy-Authenticate: e.g. "Basic", "NTLM", "Negotiate".
	[[nodiscard]] virtual auto scheme() const -> std::string = 0;

	// Produce the next token to send. server_token is the base64 blob from
	// the proxy's last Proxy-Authenticate header (empty on the first call,
	// or for schemes that don't carry one). Returns std::nullopt when the
	// negotiation cannot continue (e.g. Basic has already been sent once).
	virtual auto next_token(std::string_view server_token) -> std::optional<std::string> = 0;
};

// Base64 encode/decode. Standard alphabet, with '=' padding.
auto base64_encode(std::string_view data) -> std::string;
auto base64_decode(std::string_view data) -> std::string;

// Construct a Basic auth provider. user_pass is "user:password" (or
// "DOMAIN\user:password"); the provider base64-encodes it on demand.
auto make_basic_provider(std::string user_pass) -> std::unique_ptr<auth_provider>;

#ifdef _WIN32
// Construct an SSPI-backed provider for "NTLM" or "Negotiate". If user
// is empty, the current Windows logon credentials are used (recommended
// for Negotiate/Kerberos SSO). spn is the proxy's Kerberos SPN
// (typically "HTTP/proxy.fqdn") — required for Kerberos to resolve a
// service ticket. Throws on AcquireCredentialsHandle failure.
auto make_sspi_provider(std::string scheme, std::string spn,
                        std::string user, std::string password) -> std::unique_ptr<auth_provider>;
#endif

} // namespace wg::proxy
