// wg-tcp-tunnel - proxy_auth_sspi.cpp
// SPDX-FileCopyrightText: 2025 Arkadiusz Bokowy and contributors
// SPDX-License-Identifier: MIT

#ifdef _WIN32

#include "proxy_auth.h"

#define SECURITY_WIN32
// clang-format off
#include <windows.h>
#include <security.h>
// clang-format on

#include <stdexcept>
#include <string>

namespace wg::proxy {

namespace {

auto sspi_error(const char * what, SECURITY_STATUS s) -> std::runtime_error {
	char buf[256];
	std::snprintf(buf, sizeof(buf), "%s: SSPI status 0x%08lX", what,
	              static_cast<unsigned long>(s));
	return std::runtime_error(buf);
}

// Split "DOMAIN\\user" or "user@DOMAIN". Empty domain if neither separator
// is present. Returned strings are owning copies.
struct user_split {
	std::string user;
	std::string domain;
};
auto split_user(const std::string & s) -> user_split {
	auto bs = s.find('\\');
	if (bs != std::string::npos)
		return { s.substr(bs + 1), s.substr(0, bs) };
	auto at = s.find('@');
	if (at != std::string::npos)
		return { s.substr(0, at), s.substr(at + 1) };
	return { s, {} };
}

class sspi_provider : public auth_provider {
public:
	sspi_provider(std::string scheme, std::string spn, std::string user, std::string password)
	    : m_scheme(std::move(scheme)), m_spn(std::move(spn)) {

		SEC_WINNT_AUTH_IDENTITY_A id{};
		void * pAuth = nullptr;
		user_split split;
		if (!user.empty()) {
			split = split_user(user);
			id.User = reinterpret_cast<unsigned char *>(split.user.data());
			id.UserLength = static_cast<unsigned long>(split.user.size());
			id.Domain = reinterpret_cast<unsigned char *>(split.domain.data());
			id.DomainLength = static_cast<unsigned long>(split.domain.size());
			id.Password = reinterpret_cast<unsigned char *>(password.data());
			id.PasswordLength = static_cast<unsigned long>(password.size());
			id.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
			pAuth = &id;
		}

		TimeStamp expiry;
		SECURITY_STATUS s = AcquireCredentialsHandleA(
		    nullptr, const_cast<char *>(m_scheme.c_str()), SECPKG_CRED_OUTBOUND, nullptr, pAuth,
		    nullptr, nullptr, &m_cred, &expiry);
		if (s != SEC_E_OK)
			throw sspi_error("AcquireCredentialsHandle", s);
		m_have_cred = true;
	}

	~sspi_provider() override {
		if (m_have_ctx)
			DeleteSecurityContext(&m_ctx);
		if (m_have_cred)
			FreeCredentialsHandle(&m_cred);
	}

	sspi_provider(const sspi_provider &) = delete;
	sspi_provider & operator=(const sspi_provider &) = delete;

	[[nodiscard]] auto scheme() const -> std::string override { return m_scheme; }

	auto next_token(std::string_view server_token_b64) -> std::optional<std::string> override {
		if (m_done)
			return std::nullopt;

		// Decode server token (may be empty on first call)
		std::string in_data;
		if (!server_token_b64.empty())
			in_data = base64_decode(server_token_b64);

		SecBuffer in_buf{};
		in_buf.BufferType = SECBUFFER_TOKEN;
		in_buf.cbBuffer = static_cast<unsigned long>(in_data.size());
		in_buf.pvBuffer = in_data.empty() ? nullptr : in_data.data();
		SecBufferDesc in_desc{};
		in_desc.ulVersion = SECBUFFER_VERSION;
		in_desc.cBuffers = 1;
		in_desc.pBuffers = &in_buf;

		SecBuffer out_buf{};
		out_buf.BufferType = SECBUFFER_TOKEN;
		SecBufferDesc out_desc{};
		out_desc.ulVersion = SECBUFFER_VERSION;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = &out_buf;

		const ULONG req_attrs =
		    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT;
		ULONG ret_attrs = 0;
		TimeStamp expiry;

		SECURITY_STATUS s = InitializeSecurityContextA(
		    &m_cred, m_have_ctx ? &m_ctx : nullptr, const_cast<char *>(m_spn.c_str()), req_attrs,
		    0, SECURITY_NATIVE_DREP, in_data.empty() ? nullptr : &in_desc, 0, &m_ctx, &out_desc,
		    &ret_attrs, &expiry);
		m_have_ctx = true;

		std::optional<std::string> result;
		if (out_buf.pvBuffer != nullptr) {
			if (out_buf.cbBuffer > 0)
				result = base64_encode(std::string_view(static_cast<const char *>(out_buf.pvBuffer),
				                                        out_buf.cbBuffer));
			FreeContextBuffer(out_buf.pvBuffer);
		}

		if (s == SEC_E_OK) {
			m_done = true;
		} else if (s == SEC_I_CONTINUE_NEEDED || s == SEC_I_COMPLETE_AND_CONTINUE ||
		           s == SEC_I_COMPLETE_NEEDED) {
			// More rounds may be needed; CompleteAuthToken is required for
			// some packages (Digest); for NTLM/Negotiate it is a no-op but
			// safe to call.
			if (s == SEC_I_COMPLETE_NEEDED || s == SEC_I_COMPLETE_AND_CONTINUE)
				CompleteAuthToken(&m_ctx, &out_desc);
			if (s == SEC_I_COMPLETE_NEEDED)
				m_done = true;
		} else {
			throw sspi_error("InitializeSecurityContext", s);
		}

		return result;
	}

private:
	std::string m_scheme;
	std::string m_spn;
	CredHandle m_cred{};
	CtxtHandle m_ctx{};
	bool m_have_cred{ false };
	bool m_have_ctx{ false };
	bool m_done{ false };
};

} // anonymous namespace

auto make_sspi_provider(std::string scheme, std::string spn, std::string user,
                        std::string password) -> std::unique_ptr<auth_provider> {
	return std::make_unique<sspi_provider>(std::move(scheme), std::move(spn), std::move(user),
	                                       std::move(password));
}

} // namespace wg::proxy

#endif // _WIN32
