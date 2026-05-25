// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Authentication offered to a first-hop SOCKS5 proxy.
public enum SSHSOCKS5ProxyAuthentication: Equatable, Sendable {
    /// Offer SOCKS5 no-authentication mode.
    case none

    /// Offer SOCKS5 username/password authentication.
    case usernamePassword(username: String, password: String)
}

/// First-hop SOCKS5 proxy configuration.
public struct SSHSOCKS5ConnectionProxy: Equatable, Sendable {
    /// Host name or address.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// Authentication setting.
    public let authentication: SSHSOCKS5ProxyAuthentication

    /// Creates a SOCKS5 first-hop proxy configuration.
    public init(
        host: String,
        port: UInt16 = 1080,
        authentication: SSHSOCKS5ProxyAuthentication = .none
    ) {
        self.host = host
        self.port = port
        self.authentication = authentication
    }
}

/// Authentication offered to a first-hop HTTP CONNECT proxy.
public enum SSHHTTPConnectProxyAuthentication: Equatable, Sendable {
    /// Send the CONNECT request without proxy credentials.
    case none

    /// Send HTTP Basic credentials with the CONNECT request.
    case basic(username: String, password: String)
}

/// First-hop HTTP CONNECT proxy configuration.
public struct SSHHTTPConnectConnectionProxy: Equatable, Sendable {
    /// Host name or address.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// Authentication setting.
    public let authentication: SSHHTTPConnectProxyAuthentication

    /// Creates an HTTP CONNECT first-hop proxy configuration.
    public init(
        host: String,
        port: UInt16 = 8080,
        authentication: SSHHTTPConnectProxyAuthentication = .none
    ) {
        self.host = host
        self.port = port
        self.authentication = authentication
    }
}

/// Proxy used before opening the first SSH TCP connection.
///
/// This proxy is distinct from SSH ProxyJump. Set `connectionProxy` when the
/// network path to the first SSH endpoint goes through SOCKS5 or HTTP CONNECT.
///
/// Example:
///
/// ```swift
/// let proxy = SSHConnectionProxy.socks5(
///     SSHSOCKS5ConnectionProxy(host: "127.0.0.1", port: 1080)
/// )
/// ```
public enum SSHConnectionProxy: Equatable, Sendable {
    /// Use a SOCKS5 proxy before connecting to the SSH endpoint.
    case socks5(SSHSOCKS5ConnectionProxy)

    /// Use an HTTP CONNECT proxy before connecting to the SSH endpoint.
    case httpConnect(SSHHTTPConnectConnectionProxy)
}

extension SSHSOCKS5ProxyAuthentication {
    package var supportedMethodCodes: [UInt8] {
        switch self {
        case .none:
            [0x00]
        case .usernamePassword:
            [0x02]
        }
    }

    package func validatedCredentialBytes(
        invalidConfiguration: (String) -> any Error
    ) throws -> (username: [UInt8], password: [UInt8])? {
        switch self {
        case .none:
            return nil
        case let .usernamePassword(username, password):
            let usernameBytes = Array(username.utf8)
            let passwordBytes = Array(password.utf8)

            guard !usernameBytes.isEmpty else {
                throw invalidConfiguration(
                    "SOCKS5 username/password authentication requires a non-empty username."
                )
            }
            guard !passwordBytes.isEmpty else {
                throw invalidConfiguration(
                    "SOCKS5 username/password authentication requires a non-empty password."
                )
            }
            guard usernameBytes.count <= 255 else {
                throw invalidConfiguration(
                    "SOCKS5 usernames must fit in 255 UTF-8 bytes."
                )
            }
            guard passwordBytes.count <= 255 else {
                throw invalidConfiguration(
                    "SOCKS5 passwords must fit in 255 UTF-8 bytes."
                )
            }

            return (username: usernameBytes, password: passwordBytes)
        }
    }
}

extension SSHConnectionProxy {
    var endpoint: SSHSocketEndpoint {
        switch self {
        case let .socks5(proxy):
            SSHSocketEndpoint(host: proxy.host, port: proxy.port)
        case let .httpConnect(proxy):
            SSHSocketEndpoint(host: proxy.host, port: proxy.port)
        }
    }
}
