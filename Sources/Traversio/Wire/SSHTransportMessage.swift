// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHDisconnectReasonCode: RawRepresentable, Equatable, Hashable, Sendable {
    let rawValue: UInt32

    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    static let hostNotAllowedToConnect = Self(rawValue: 1)
    static let protocolError = Self(rawValue: 2)
    static let keyExchangeFailed = Self(rawValue: 3)
    static let reserved = Self(rawValue: 4)
    static let macError = Self(rawValue: 5)
    static let compressionError = Self(rawValue: 6)
    static let serviceNotAvailable = Self(rawValue: 7)
    static let protocolVersionNotSupported = Self(rawValue: 8)
    static let hostKeyNotVerifiable = Self(rawValue: 9)
    static let connectionLost = Self(rawValue: 10)
    static let byApplication = Self(rawValue: 11)
    static let tooManyConnections = Self(rawValue: 12)
    static let authCancelledByUser = Self(rawValue: 13)
    static let noMoreAuthMethodsAvailable = Self(rawValue: 14)
    static let illegalUserName = Self(rawValue: 15)
}

package enum SSHTransportMessageID: UInt8, Equatable, Sendable {
    case disconnect = 1
    case ignore = 2
    case unimplemented = 3
    case debug = 4
    case serviceRequest = 5
    case serviceAccept = 6
    case extensionInfo = 7
    case keyExchangeInit = 20
    case newKeys = 21
    case keyExchangeECDHInit = 30
    case keyExchangeECDHReply = 31
}

struct SSHDisconnectMessage: Equatable, Sendable {
    let reasonCode: SSHDisconnectReasonCode
    let description: String
    let languageTag: String
}

struct SSHIgnoreMessage: Equatable, Sendable {
    let data: [UInt8]
}

struct SSHUnimplementedMessage: Equatable, Sendable {
    let packetSequenceNumber: UInt32
}

struct SSHDebugMessage: Equatable, Sendable {
    let alwaysDisplay: Bool
    let message: String
    let languageTag: String
}

struct SSHServiceRequestMessage: Equatable, Sendable {
    let serviceName: String
}

struct SSHServiceAcceptMessage: Equatable, Sendable {
    let serviceName: String
}

struct SSHExtensionInfoEntry: Equatable, Sendable {
    let name: String
    let value: [UInt8]
}

struct SSHExtensionInfoMessage: Equatable, Sendable {
    let entries: [SSHExtensionInfoEntry]
}

struct SSHKeyExchangeInitMessage: Equatable, Sendable {
    let cookie: [UInt8]
    let keyExchangeAlgorithms: [String]
    let serverHostKeyAlgorithms: [String]
    let encryptionAlgorithmsClientToServer: [String]
    let encryptionAlgorithmsServerToClient: [String]
    let macAlgorithmsClientToServer: [String]
    let macAlgorithmsServerToClient: [String]
    let compressionAlgorithmsClientToServer: [String]
    let compressionAlgorithmsServerToClient: [String]
    let languagesClientToServer: [String]
    let languagesServerToClient: [String]
    let firstKeyExchangePacketFollows: Bool
    let reserved: UInt32

    init(
        cookie: [UInt8],
        keyExchangeAlgorithms: [String],
        serverHostKeyAlgorithms: [String],
        encryptionAlgorithmsClientToServer: [String],
        encryptionAlgorithmsServerToClient: [String],
        macAlgorithmsClientToServer: [String],
        macAlgorithmsServerToClient: [String],
        compressionAlgorithmsClientToServer: [String],
        compressionAlgorithmsServerToClient: [String],
        languagesClientToServer: [String] = [],
        languagesServerToClient: [String] = [],
        firstKeyExchangePacketFollows: Bool = false,
        reserved: UInt32 = 0
    ) throws {
        guard cookie.count == 16 else {
            throw SSHWireError.invalidKeyExchangeCookieLength(cookie.count)
        }

        try Self.requireNonEmpty(keyExchangeAlgorithms, field: "kex_algorithms")
        try Self.requireNonEmpty(serverHostKeyAlgorithms, field: "server_host_key_algorithms")
        try Self.requireNonEmpty(
            encryptionAlgorithmsClientToServer,
            field: "encryption_algorithms_client_to_server"
        )
        try Self.requireNonEmpty(
            encryptionAlgorithmsServerToClient,
            field: "encryption_algorithms_server_to_client"
        )
        try Self.requireNonEmpty(
            macAlgorithmsClientToServer,
            field: "mac_algorithms_client_to_server"
        )
        try Self.requireNonEmpty(
            macAlgorithmsServerToClient,
            field: "mac_algorithms_server_to_client"
        )
        try Self.requireNonEmpty(
            compressionAlgorithmsClientToServer,
            field: "compression_algorithms_client_to_server"
        )
        try Self.requireNonEmpty(
            compressionAlgorithmsServerToClient,
            field: "compression_algorithms_server_to_client"
        )

        self.cookie = cookie
        self.keyExchangeAlgorithms = keyExchangeAlgorithms
        self.serverHostKeyAlgorithms = serverHostKeyAlgorithms
        self.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer
        self.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient
        self.macAlgorithmsClientToServer = macAlgorithmsClientToServer
        self.macAlgorithmsServerToClient = macAlgorithmsServerToClient
        self.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer
        self.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient
        self.languagesClientToServer = languagesClientToServer
        self.languagesServerToClient = languagesServerToClient
        self.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows
        self.reserved = reserved
    }

    private static func requireNonEmpty(_ values: [String], field: String) throws {
        guard !values.isEmpty else {
            throw SSHWireError.emptyRequiredNameList(field)
        }
    }
}

struct SSHNewKeysMessage: Equatable, Sendable {
    init() {}
}

struct SSHKeyExchangeECDHInitMessage: Equatable, Sendable {
    let publicKey: [UInt8]
}

struct SSHKeyExchangeECDHReplyMessage: Equatable, Sendable {
    let hostKey: [UInt8]
    let publicKey: [UInt8]
    let signature: [UInt8]
}

enum SSHTransportMessage: Equatable, Sendable {
    case disconnect(SSHDisconnectMessage)
    case ignore(SSHIgnoreMessage)
    case unimplemented(SSHUnimplementedMessage)
    case debug(SSHDebugMessage)
    case serviceRequest(SSHServiceRequestMessage)
    case serviceAccept(SSHServiceAcceptMessage)
    case extensionInfo(SSHExtensionInfoMessage)
    case keyExchangeInit(SSHKeyExchangeInitMessage)
    case newKeys(SSHNewKeysMessage)
    case keyExchangeECDHInit(SSHKeyExchangeECDHInitMessage)
    case keyExchangeECDHReply(SSHKeyExchangeECDHReplyMessage)

    var messageID: SSHTransportMessageID {
        switch self {
        case .disconnect:
            return .disconnect
        case .ignore:
            return .ignore
        case .unimplemented:
            return .unimplemented
        case .debug:
            return .debug
        case .serviceRequest:
            return .serviceRequest
        case .serviceAccept:
            return .serviceAccept
        case .extensionInfo:
            return .extensionInfo
        case .keyExchangeInit:
            return .keyExchangeInit
        case .newKeys:
            return .newKeys
        case .keyExchangeECDHInit:
            return .keyExchangeECDHInit
        case .keyExchangeECDHReply:
            return .keyExchangeECDHReply
        }
    }
}
