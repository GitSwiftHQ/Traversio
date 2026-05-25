// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Authentication banner sent by the server during user authentication.
public struct SSHAuthenticationBanner: Equatable, Sendable {
    /// Diagnostic or server-provided message.
    public let message: String
    /// Server-provided language tag.
    public let languageTag: String
    /// Creates an SSHAuthenticationBanner.

    public init(message: String, languageTag: String) {
        self.message = message
        self.languageTag = languageTag
    }
}

/// Result of SSH auth-method discovery using the `none` userauth method.
public struct SSHAuthenticationMethodDiscoveryResult: Equatable, Sendable {
    /// SSH username.
    public let username: String
    /// Service Name.
    public let serviceName: String
    /// Available Methods.
    public let availableMethods: [String]
    /// Partial Success.
    public let partialSuccess: Bool
    /// Allows Unauthenticated Access.
    public let allowsUnauthenticatedAccess: Bool
    /// Authentication banners sent by the server.
    public let banners: [SSHAuthenticationBanner]
    /// Creates an SSHAuthenticationMethodDiscoveryResult.

    public init(
        username: String,
        serviceName: String,
        availableMethods: [String],
        partialSuccess: Bool,
        allowsUnauthenticatedAccess: Bool,
        banners: [SSHAuthenticationBanner] = []
    ) {
        self.username = username
        self.serviceName = serviceName
        self.availableMethods = availableMethods
        self.partialSuccess = partialSuccess
        self.allowsUnauthenticatedAccess = allowsUnauthenticatedAccess
        self.banners = banners
    }
}

/// Configuration for auth-method discovery.
///
/// Discovery still performs SSH transport setup and host-key verification; it
/// does not authenticate as the user.
public struct SSHAuthenticationMethodDiscoveryConfiguration: Equatable, Sendable {
    /// Host name or address.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// SSH username.
    public let username: String
    /// Host-key verification policy.
    public let hostKeyPolicy: SSHHostKeyPolicy
    /// Compression preference.
    public let compressionPreference: SSHCompressionPreference
    /// Legacy algorithm compatibility options.
    public let legacyAlgorithmOptions: SSHLegacyAlgorithmOptions
    /// Timeout policy.
    public let timeoutPolicy: SSHTimeoutPolicy
    /// First-hop connection proxy.
    public let connectionProxy: SSHConnectionProxy?
    /// ProxyJump hosts used before the final target.
    public let proxyJumpHosts: [SSHProxyJumpHost]
    /// Creates an SSHAuthenticationMethodDiscoveryConfiguration.

    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        hostKeyPolicy: SSHHostKeyPolicy,
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled,
        timeoutPolicy: SSHTimeoutPolicy = .currentProfileDefault,
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = []
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.hostKeyPolicy = hostKeyPolicy
        self.compressionPreference = compressionPreference
        self.legacyAlgorithmOptions = legacyAlgorithmOptions
        self.timeoutPolicy = timeoutPolicy
        self.connectionProxy = connectionProxy
        self.proxyJumpHosts = proxyJumpHosts
    }
}
