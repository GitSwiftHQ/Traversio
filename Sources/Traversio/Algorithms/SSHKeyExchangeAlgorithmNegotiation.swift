// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

enum SSHAlgorithmCategory: String, Equatable, Sendable {
    case keyExchange = "key exchange"
    case serverHostKey = "server host key"
    case encryptionClientToServer = "client-to-server encryption"
    case encryptionServerToClient = "server-to-client encryption"
    case macClientToServer = "client-to-server MAC"
    case macServerToClient = "server-to-client MAC"
    case compressionClientToServer = "client-to-server compression"
    case compressionServerToClient = "server-to-client compression"
}

enum SSHAlgorithmNegotiationError: Error, Equatable, Sendable {
    case noCommonAlgorithm(SSHAlgorithmCategory)
}

struct SSHNegotiatedAlgorithms: Equatable, Sendable {
    let keyExchangeAlgorithm: String
    let serverHostKeyAlgorithm: String
    let encryptionAlgorithmClientToServer: String
    let encryptionAlgorithmServerToClient: String
    let macAlgorithmClientToServer: String
    let macAlgorithmServerToClient: String
    let compressionAlgorithmClientToServer: String
    let compressionAlgorithmServerToClient: String
    let languageClientToServer: String?
    let languageServerToClient: String?
}

package struct SSHKeyExchangeInitNegotiation: Equatable, Sendable {
    let localProposal: SSHKeyExchangeInitMessage
    let remoteProposal: SSHKeyExchangeInitMessage
    let algorithms: SSHNegotiatedAlgorithms
    let usesStrictKeyExchange: Bool
    let shouldIgnoreNextPacketFromServer: Bool
}

struct SSHClientKeyExchangePreferences: Equatable, Sendable {
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

    static let `default` = Self(
        keyExchangeAlgorithms: [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "ext-info-c",
            "kex-strict-c-v00@openssh.com",
        ],
        serverHostKeyAlgorithms: [
            "ssh-ed25519",
            "ssh-ed25519-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "rsa-sha2-512",
            "rsa-sha2-256",
        ],
        encryptionAlgorithmsClientToServer: [
            "aes128-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
        ],
        encryptionAlgorithmsServerToClient: [
            "aes128-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
        ],
        macAlgorithmsClientToServer: [
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
        ],
        macAlgorithmsServerToClient: [
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
        ],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"],
        languagesClientToServer: [],
        languagesServerToClient: [],
        firstKeyExchangePacketFollows: false
    )

    func makeKeyExchangeInitMessage(cookie: [UInt8]) throws -> SSHKeyExchangeInitMessage {
        try self.makeKeyExchangeInitMessage(
            cookie: cookie,
            keyExchangeAlgorithms: self.keyExchangeAlgorithms
        )
    }

    func makeReexchangeKeyExchangeInitMessage(cookie: [UInt8]) throws -> SSHKeyExchangeInitMessage {
        try self.makeKeyExchangeInitMessage(
            cookie: cookie,
            keyExchangeAlgorithms: self.reexchangeKeyExchangeAlgorithms
        )
    }

    func makeKeyExchangeInitMessage() throws -> SSHKeyExchangeInitMessage {
        var generator = SystemRandomNumberGenerator()
        return try self.makeKeyExchangeInitMessage(using: &generator)
    }

    func makeReexchangeKeyExchangeInitMessage() throws -> SSHKeyExchangeInitMessage {
        var generator = SystemRandomNumberGenerator()
        return try self.makeReexchangeKeyExchangeInitMessage(using: &generator)
    }

    func makeKeyExchangeInitMessage<T: RandomNumberGenerator>(
        using generator: inout T
    ) throws -> SSHKeyExchangeInitMessage {
        try self.makeKeyExchangeInitMessage(
            cookie: Self.makeCookie(using: &generator)
        )
    }

    func makeReexchangeKeyExchangeInitMessage<T: RandomNumberGenerator>(
        using generator: inout T
    ) throws -> SSHKeyExchangeInitMessage {
        try self.makeReexchangeKeyExchangeInitMessage(
            cookie: Self.makeCookie(using: &generator)
        )
    }

    private func makeKeyExchangeInitMessage(
        cookie: [UInt8],
        keyExchangeAlgorithms: [String]
    ) throws -> SSHKeyExchangeInitMessage {
        try SSHKeyExchangeInitMessage(
            cookie: cookie,
            keyExchangeAlgorithms: keyExchangeAlgorithms,
            serverHostKeyAlgorithms: self.serverHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer: self.encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient: self.encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer: self.macAlgorithmsClientToServer,
            macAlgorithmsServerToClient: self.macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer: self.compressionAlgorithmsClientToServer,
            compressionAlgorithmsServerToClient: self.compressionAlgorithmsServerToClient,
            languagesClientToServer: self.languagesClientToServer,
            languagesServerToClient: self.languagesServerToClient,
            firstKeyExchangePacketFollows: self.firstKeyExchangePacketFollows
        )
    }

    private var reexchangeKeyExchangeAlgorithms: [String] {
        self.keyExchangeAlgorithms.filter {
            $0 != "ext-info-c" && $0 != "kex-strict-c-v00@openssh.com"
        }
    }

    private static func makeCookie<T: RandomNumberGenerator>(using generator: inout T) -> [UInt8] {
        (0..<16).map { _ in
            UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        }
    }
}

extension SSHClientKeyExchangePreferences {
    func withCompressionAlgorithms(
        clientToServer algorithmsClientToServer: [String],
        serverToClient algorithmsServerToClient: [String]
    ) -> Self {
        Self(
            keyExchangeAlgorithms: self.keyExchangeAlgorithms,
            serverHostKeyAlgorithms: self.serverHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer: self.encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient: self.encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer: self.macAlgorithmsClientToServer,
            macAlgorithmsServerToClient: self.macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer: algorithmsClientToServer,
            compressionAlgorithmsServerToClient: algorithmsServerToClient,
            languagesClientToServer: self.languagesClientToServer,
            languagesServerToClient: self.languagesServerToClient,
            firstKeyExchangePacketFollows: self.firstKeyExchangePacketFollows
        )
    }

    func withServerHostKeyAlgorithms(_ algorithms: [String]) -> Self {
        Self(
            keyExchangeAlgorithms: self.keyExchangeAlgorithms,
            serverHostKeyAlgorithms: algorithms,
            encryptionAlgorithmsClientToServer: self.encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient: self.encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer: self.macAlgorithmsClientToServer,
            macAlgorithmsServerToClient: self.macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer: self.compressionAlgorithmsClientToServer,
            compressionAlgorithmsServerToClient: self.compressionAlgorithmsServerToClient,
            languagesClientToServer: self.languagesClientToServer,
            languagesServerToClient: self.languagesServerToClient,
            firstKeyExchangePacketFollows: self.firstKeyExchangePacketFollows
        )
    }
}

struct SSHKeyExchangeAlgorithmNegotiator: Sendable {
    func negotiate(
        localProposal: SSHKeyExchangeInitMessage,
        remoteProposal: SSHKeyExchangeInitMessage
    ) throws -> SSHKeyExchangeInitNegotiation {
        let localKeyExchangeAlgorithms = self.negotiableKeyExchangeAlgorithms(
            localProposal.keyExchangeAlgorithms
        )
        let remoteKeyExchangeAlgorithms = self.negotiableKeyExchangeAlgorithms(
            remoteProposal.keyExchangeAlgorithms
        )
        let encryptionAlgorithmClientToServer = try self.selectAlgorithm(
            localProposal.encryptionAlgorithmsClientToServer,
            remoteProposal.encryptionAlgorithmsClientToServer,
            category: .encryptionClientToServer
        )
        let encryptionAlgorithmServerToClient = try self.selectAlgorithm(
            localProposal.encryptionAlgorithmsServerToClient,
            remoteProposal.encryptionAlgorithmsServerToClient,
            category: .encryptionServerToClient
        )
        let algorithms = try SSHNegotiatedAlgorithms(
            keyExchangeAlgorithm: self.selectAlgorithm(
                localKeyExchangeAlgorithms,
                remoteKeyExchangeAlgorithms,
                category: .keyExchange
            ),
            serverHostKeyAlgorithm: self.selectAlgorithm(
                localProposal.serverHostKeyAlgorithms,
                remoteProposal.serverHostKeyAlgorithms,
                category: .serverHostKey
            ),
            encryptionAlgorithmClientToServer: encryptionAlgorithmClientToServer,
            encryptionAlgorithmServerToClient: encryptionAlgorithmServerToClient,
            macAlgorithmClientToServer: try self.selectMACAlgorithm(
                localProposal.macAlgorithmsClientToServer,
                remoteProposal.macAlgorithmsClientToServer,
                encryptionAlgorithm: encryptionAlgorithmClientToServer,
                category: .macClientToServer
            ),
            macAlgorithmServerToClient: try self.selectMACAlgorithm(
                localProposal.macAlgorithmsServerToClient,
                remoteProposal.macAlgorithmsServerToClient,
                encryptionAlgorithm: encryptionAlgorithmServerToClient,
                category: .macServerToClient
            ),
            compressionAlgorithmClientToServer: self.selectAlgorithm(
                localProposal.compressionAlgorithmsClientToServer,
                remoteProposal.compressionAlgorithmsClientToServer,
                category: .compressionClientToServer
            ),
            compressionAlgorithmServerToClient: self.selectAlgorithm(
                localProposal.compressionAlgorithmsServerToClient,
                remoteProposal.compressionAlgorithmsServerToClient,
                category: .compressionServerToClient
            ),
            languageClientToServer: self.selectOptionalValue(
                localProposal.languagesClientToServer,
                remoteProposal.languagesClientToServer
            ),
            languageServerToClient: self.selectOptionalValue(
                localProposal.languagesServerToClient,
                remoteProposal.languagesServerToClient
            )
        )

        return SSHKeyExchangeInitNegotiation(
            localProposal: localProposal,
            remoteProposal: remoteProposal,
            algorithms: algorithms,
            usesStrictKeyExchange: self.usesStrictKeyExchange(
                localProposal: localProposal,
                remoteProposal: remoteProposal
            ),
            shouldIgnoreNextPacketFromServer: remoteProposal.firstKeyExchangePacketFollows
                && !self.isPeerGuessCorrect(
                    localProposal: localProposal,
                    remoteProposal: remoteProposal,
                    algorithms: algorithms
                )
        )
    }

    private func selectAlgorithm(
        _ localValues: [String],
        _ remoteValues: [String],
        category: SSHAlgorithmCategory
    ) throws -> String {
        for algorithm in localValues where remoteValues.contains(algorithm) {
            return algorithm
        }

        throw SSHAlgorithmNegotiationError.noCommonAlgorithm(category)
    }

    private func selectMACAlgorithm(
        _ localValues: [String],
        _ remoteValues: [String],
        encryptionAlgorithm: String,
        category: SSHAlgorithmCategory
    ) throws -> String {
        if Self.isAEADEncryptionAlgorithm(encryptionAlgorithm) {
            return self.selectOptionalValue(localValues, remoteValues) ?? localValues[0]
        }

        return try self.selectAlgorithm(
            localValues,
            remoteValues,
            category: category
        )
    }

    private func negotiableKeyExchangeAlgorithms(_ values: [String]) -> [String] {
        values.filter { !Self.isKeyExchangeExtensionMarker($0) }
    }

    private static func isAEADEncryptionAlgorithm(_ value: String) -> Bool {
        switch value {
        case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com":
            return true
        default:
            return false
        }
    }

    private func selectOptionalValue(_ localValues: [String], _ remoteValues: [String]) -> String? {
        for value in localValues where remoteValues.contains(value) {
            return value
        }

        return nil
    }

    private func isPeerGuessCorrect(
        localProposal: SSHKeyExchangeInitMessage,
        remoteProposal: SSHKeyExchangeInitMessage,
        algorithms: SSHNegotiatedAlgorithms
    ) -> Bool {
        self.negotiableKeyExchangeAlgorithms(localProposal.keyExchangeAlgorithms).first
            == algorithms.keyExchangeAlgorithm
            && self.negotiableKeyExchangeAlgorithms(remoteProposal.keyExchangeAlgorithms).first
            == algorithms.keyExchangeAlgorithm
            && localProposal.serverHostKeyAlgorithms.first == algorithms.serverHostKeyAlgorithm
            && remoteProposal.serverHostKeyAlgorithms.first == algorithms.serverHostKeyAlgorithm
    }

    private func usesStrictKeyExchange(
        localProposal: SSHKeyExchangeInitMessage,
        remoteProposal: SSHKeyExchangeInitMessage
    ) -> Bool {
        localProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com")
            && remoteProposal.keyExchangeAlgorithms.contains("kex-strict-s-v00@openssh.com")
    }

    private static func isKeyExchangeExtensionMarker(_ algorithm: String) -> Bool {
        algorithm.hasPrefix("ext-info-") || algorithm.hasPrefix("kex-strict-")
    }
}
