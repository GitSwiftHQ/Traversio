// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHTransportProtocolSetupPhase: Equatable, Sendable {
    case identification
    case keyExchange
    case authentication
    case authenticated
}

package struct SSHTransportProtocolNegotiatedAlgorithmsSnapshot: Equatable, Sendable {
    package let keyExchangeAlgorithm: String
    package let serverHostKeyAlgorithm: String
    package let encryptionAlgorithmClientToServer: String
    package let encryptionAlgorithmServerToClient: String
    package let macAlgorithmClientToServer: String
    package let macAlgorithmServerToClient: String
    package let compressionAlgorithmClientToServer: String
    package let compressionAlgorithmServerToClient: String
    package let usesStrictKeyExchange: Bool

    package var effectiveIntegrityAlgorithmClientToServer: String {
        Self.effectiveIntegrityAlgorithm(
            encryptionAlgorithm: self.encryptionAlgorithmClientToServer,
            macAlgorithm: self.macAlgorithmClientToServer
        )
    }

    package var effectiveIntegrityAlgorithmServerToClient: String {
        Self.effectiveIntegrityAlgorithm(
            encryptionAlgorithm: self.encryptionAlgorithmServerToClient,
            macAlgorithm: self.macAlgorithmServerToClient
        )
    }

    init(algorithms: SSHNegotiatedAlgorithms, usesStrictKeyExchange: Bool) {
        self.keyExchangeAlgorithm = algorithms.keyExchangeAlgorithm
        self.serverHostKeyAlgorithm = algorithms.serverHostKeyAlgorithm
        self.encryptionAlgorithmClientToServer = algorithms.encryptionAlgorithmClientToServer
        self.encryptionAlgorithmServerToClient = algorithms.encryptionAlgorithmServerToClient
        self.macAlgorithmClientToServer = algorithms.macAlgorithmClientToServer
        self.macAlgorithmServerToClient = algorithms.macAlgorithmServerToClient
        self.compressionAlgorithmClientToServer = algorithms.compressionAlgorithmClientToServer
        self.compressionAlgorithmServerToClient = algorithms.compressionAlgorithmServerToClient
        self.usesStrictKeyExchange = usesStrictKeyExchange
    }

    package static func effectiveIntegrityAlgorithm(
        encryptionAlgorithm: String,
        macAlgorithm: String
    ) -> String {
        switch encryptionAlgorithm {
        case "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com":
            return "implicit"
        default:
            return macAlgorithm
        }
    }
}

package struct SSHTransportProtocolRemoteDisconnectSnapshot: Equatable, Sendable {
    package let reasonCode: UInt32
    package let description: String
    package let languageTag: String

    init(message: SSHDisconnectMessage) {
        self.reasonCode = message.reasonCode.rawValue
        self.description = message.description
        self.languageTag = message.languageTag
    }
}

package struct SSHTransportProtocolRemoteDebugSnapshot: Equatable, Sendable {
    package let alwaysDisplay: Bool
    package let message: String
    package let languageTag: String

    init(message: SSHDebugMessage) {
        self.alwaysDisplay = message.alwaysDisplay
        self.message = message.message
        self.languageTag = message.languageTag
    }
}

package struct SSHTransportProtocolDiagnosticsSnapshot: Equatable, Sendable {
    package let phase: SSHTransportProtocolSetupPhase
    package let clientIdentification: String
    package let remoteIdentification: String?
    package let preIdentificationLines: [String]
    package let keepaliveIntervalNanoseconds: UInt64?
    package let keepaliveReplyTimeoutNanoseconds: UInt64?
    package let responseTimeoutNanoseconds: UInt64?
    package let negotiatedAlgorithms: SSHTransportProtocolNegotiatedAlgorithmsSnapshot?
    package let didReceiveServerExtensionInfo: Bool
    package let serverExtensionNames: [String]
    package let serverSignatureAlgorithms: [String]?
    package let remoteDisconnect: SSHTransportProtocolRemoteDisconnectSnapshot?
    package let remoteDebugMessages: [SSHTransportProtocolRemoteDebugSnapshot]
}
