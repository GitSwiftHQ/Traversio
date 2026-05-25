// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// Algorithm list category reported by `SSHSupportedAlgorithms`.
public enum SSHSupportedAlgorithmCategory: CaseIterable, Equatable, Hashable, Sendable {
    /// key exchange.
    case keyExchange
    /// Server host key.
    case serverHostKey
    /// Encryption Client To Server.
    case encryptionClientToServer
    /// Encryption Server To Client.
    case encryptionServerToClient
    /// MAC Client To Server.
    case macClientToServer
    /// MAC Server To Client.
    case macServerToClient
    /// Compression Client To Server.
    case compressionClientToServer
    /// Compression Server To Client.
    case compressionServerToClient
    /// public key Signature.
    case publicKeySignature
}

/// Public view of the algorithms Traversio advertises for the current profile.
///
/// Use this for capability display or preflight checks. It is not a negotiation
/// result for a particular connection; negotiated values are exposed through
/// diagnostics after setup.
public struct SSHSupportedAlgorithms: Equatable, Sendable {
    /// key exchange Algorithms.
    public let keyExchangeAlgorithms: [String]
    /// Server host key Algorithms.
    public let serverHostKeyAlgorithms: [String]
    /// Encryption Algorithms Client To Server.
    public let encryptionAlgorithmsClientToServer: [String]
    /// Encryption Algorithms Server To Client.
    public let encryptionAlgorithmsServerToClient: [String]
    /// MAC Algorithms Client To Server.
    public let macAlgorithmsClientToServer: [String]
    /// MAC Algorithms Server To Client.
    public let macAlgorithmsServerToClient: [String]
    /// Compression Algorithms Client To Server.
    public let compressionAlgorithmsClientToServer: [String]
    /// Compression Algorithms Server To Client.
    public let compressionAlgorithmsServerToClient: [String]
    /// public key Signature Algorithms.
    public let publicKeySignatureAlgorithms: [String]

    /// Current Profile.
    public static let currentProfile = Self()

    /// Creates an SSHSupportedAlgorithms.
    public init(
        keyExchangeAlgorithms: [String],
        serverHostKeyAlgorithms: [String],
        encryptionAlgorithmsClientToServer: [String],
        encryptionAlgorithmsServerToClient: [String],
        macAlgorithmsClientToServer: [String],
        macAlgorithmsServerToClient: [String],
        compressionAlgorithmsClientToServer: [String],
        compressionAlgorithmsServerToClient: [String],
        publicKeySignatureAlgorithms: [String]
    ) {
        self.keyExchangeAlgorithms = keyExchangeAlgorithms
        self.serverHostKeyAlgorithms = serverHostKeyAlgorithms
        self.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer
        self.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient
        self.macAlgorithmsClientToServer = macAlgorithmsClientToServer
        self.macAlgorithmsServerToClient = macAlgorithmsServerToClient
        self.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer
        self.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient
        self.publicKeySignatureAlgorithms = publicKeySignatureAlgorithms
    }

    /// Creates an SSHSupportedAlgorithms.
    public init(
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled
    ) {
        let preferences = SSHClientKeyExchangePreferences.default
            .withCompressionAlgorithms(
                clientToServer: compressionPreference.keyExchangeCompressionAlgorithms,
                serverToClient: compressionPreference.keyExchangeCompressionAlgorithms
            )
            .withServerHostKeyAlgorithms(
                legacyAlgorithmOptions.preferredServerHostKeyAlgorithms
            )

        self.init(
            keyExchangeAlgorithms: preferences.keyExchangeAlgorithms.filter {
                !Self.isKeyExchangeExtensionMarker($0)
            },
            serverHostKeyAlgorithms: preferences.serverHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer: preferences.encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient: preferences.encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer: preferences.macAlgorithmsClientToServer,
            macAlgorithmsServerToClient: preferences.macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer: preferences.compressionAlgorithmsClientToServer,
            compressionAlgorithmsServerToClient: preferences.compressionAlgorithmsServerToClient,
            publicKeySignatureAlgorithms: [
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            ] + legacyAlgorithmOptions.preferredRSAPublicKeyAuthenticationAlgorithms
        )
    }

    /// Returns the algorithm names for one category.
    public func algorithms(for category: SSHSupportedAlgorithmCategory) -> [String] {
        switch category {
        case .keyExchange:
            return self.keyExchangeAlgorithms
        case .serverHostKey:
            return self.serverHostKeyAlgorithms
        case .encryptionClientToServer:
            return self.encryptionAlgorithmsClientToServer
        case .encryptionServerToClient:
            return self.encryptionAlgorithmsServerToClient
        case .macClientToServer:
            return self.macAlgorithmsClientToServer
        case .macServerToClient:
            return self.macAlgorithmsServerToClient
        case .compressionClientToServer:
            return self.compressionAlgorithmsClientToServer
        case .compressionServerToClient:
            return self.compressionAlgorithmsServerToClient
        case .publicKeySignature:
            return self.publicKeySignatureAlgorithms
        }
    }

    private static func isKeyExchangeExtensionMarker(_ algorithm: String) -> Bool {
        algorithm.hasPrefix("ext-info-") || algorithm.hasPrefix("kex-strict-")
    }
}

extension SSHClientConfiguration {
    /// Supported Algorithms.
    public var supportedAlgorithms: SSHSupportedAlgorithms {
        SSHSupportedAlgorithms(
            compressionPreference: self.compressionPreference,
            legacyAlgorithmOptions: self.legacyAlgorithmOptions
        )
    }
}

/// Supported algorithms.
extension SSHProxyJumpHost {
    /// Supported Algorithms.
    public var supportedAlgorithms: SSHSupportedAlgorithms {
        SSHSupportedAlgorithms(
            compressionPreference: self.compressionPreference,
            legacyAlgorithmOptions: self.legacyAlgorithmOptions
        )
    }
}
