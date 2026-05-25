// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Testing
@testable import Traversio

let backgroundKeepaliveTestInterval = 0.05
// These tests use real Task.sleep-based timers and run under Swift Testing's
// full-suite concurrent load, so keep the observation window wider than the
// protocol interval being tested.
let backgroundKeepaliveObservationAttempts = 1_000
let backgroundKeepaliveObservationSleepNanoseconds: UInt64 = 5_000_000

enum EmptyReceiveBehavior: Sendable {
    case endOfStream
    case delayedEndOfStream(delayNanoseconds: UInt64, ignoreCancellation: Bool)
    case waitForAppendedChunks
}

actor ProtocolClientMockSSHByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    private var receiveChunks: [SSHByteStreamChunk]
    private var sent: [[UInt8]] = []
    private var sentEndOfStreamFlags: [Bool] = []
    private var queuedSendFailureCodes: [POSIXErrorCode] = []
    private let emptyReceiveBehavior: EmptyReceiveBehavior
    private let receiveDelayNanoseconds: UInt64
    private let sendDelayNanoseconds: UInt64
    private var activeReceiveCount = 0
    private var maximumConcurrentReceiveCount = 0
    private var activeSendCount = 0
    private var maximumConcurrentSendCount = 0

    init(
        receiveChunks: [SSHByteStreamChunk],
        emptyReceiveBehavior: EmptyReceiveBehavior = .endOfStream,
        receiveDelayNanoseconds: UInt64 = 0,
        sendDelayNanoseconds: UInt64 = 0
    ) {
        self.receiveChunks = receiveChunks
        self.emptyReceiveBehavior = emptyReceiveBehavior
        self.receiveDelayNanoseconds = receiveDelayNanoseconds
        self.sendDelayNanoseconds = sendDelayNanoseconds
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        try await self.send(bytes, endOfStream: endOfStream, respectCancellation: true)
    }

    func send(
        _ bytes: [UInt8],
        endOfStream: Bool,
        respectCancellation: Bool
    ) async throws {
        self.activeSendCount += 1
        self.maximumConcurrentSendCount = max(
            self.maximumConcurrentSendCount,
            self.activeSendCount
        )
        defer {
            self.activeSendCount -= 1
        }

        if self.sendDelayNanoseconds > 0 {
            if respectCancellation {
                try await Task.sleep(nanoseconds: self.sendDelayNanoseconds)
            } else {
                try? await Task.sleep(nanoseconds: self.sendDelayNanoseconds)
            }
        }

        if !self.queuedSendFailureCodes.isEmpty {
            throw POSIXError(self.queuedSendFailureCodes.removeFirst())
        }
        self.sent.append(bytes)
        self.sentEndOfStreamFlags.append(endOfStream)
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        try await self.receive(
            atLeast: minimum,
            atMost: maximum,
            respectCancellation: true
        )
    }

    func receive(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        self.activeReceiveCount += 1
        self.maximumConcurrentReceiveCount = max(
            self.maximumConcurrentReceiveCount,
            self.activeReceiveCount
        )
        defer {
            self.activeReceiveCount -= 1
        }

        if self.receiveDelayNanoseconds > 0 {
            if respectCancellation {
                try await Task.sleep(nanoseconds: self.receiveDelayNanoseconds)
            } else {
                try? await Task.sleep(nanoseconds: self.receiveDelayNanoseconds)
            }
        }

        if self.receiveChunks.isEmpty {
            switch self.emptyReceiveBehavior {
            case .endOfStream:
                return SSHByteStreamChunk(bytes: [], endOfStream: true)
            case let .delayedEndOfStream(delayNanoseconds, ignoreCancellation):
                if ignoreCancellation {
                    try? await Task.sleep(nanoseconds: delayNanoseconds)
                } else {
                    try await Task.sleep(nanoseconds: delayNanoseconds)
                }
                return SSHByteStreamChunk(bytes: [], endOfStream: true)
            case .waitForAppendedChunks:
                while self.receiveChunks.isEmpty {
                    if respectCancellation {
                        try Task.checkCancellation()
                    }
                    await Task.yield()
                }
            }
        }

        return self.receiveChunks.removeFirst()
    }

    func sentPayloads() -> [[UInt8]] {
        self.sent
    }

    func sentPayloadEndOfStreamFlags() -> [Bool] {
        self.sentEndOfStreamFlags
    }

    func remainingReceiveChunkCount() -> Int {
        self.receiveChunks.count
    }

    func appendReceiveChunks(_ chunks: [SSHByteStreamChunk]) {
        self.receiveChunks.append(contentsOf: chunks)
    }

    func enqueueSendFailure(_ code: POSIXErrorCode) {
        self.queuedSendFailureCodes.append(code)
    }

    func maximumConcurrentReceiveCountObserved() -> Int {
        self.maximumConcurrentReceiveCount
    }

    func activeReceiveCountObserved() -> Int {
        self.activeReceiveCount
    }

    func maximumConcurrentSendCountObserved() -> Int {
        self.maximumConcurrentSendCount
    }

    func activeSendCountObserved() -> Int {
        self.activeSendCount
    }
}

actor ConnectionFixtureMockSSHByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    private let serverPayloadsAfterNewKeys: [[UInt8]]
    private let encryptedChunkSize: Int?
    private let emptyReceiveBehavior: EmptyReceiveBehavior
    private let receiveDelayNanoseconds: UInt64
    private let remoteIdentificationLine = Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8)
    private let remoteIdentification = try! SSHIdentification(
        rawValue: "SSH-2.0-OpenSSH_9.9 test"
    )
    private let remoteProposal = try! SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    private let hostSigningKey = try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(Array(0x01...0x20))
    )
    private let serverKeyAgreementKey = try! Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )

    private var receiveChunks: [SSHByteStreamChunk]
    private var sent: [[UInt8]] = []
    private var sentEndOfStreamFlags: [Bool] = []
    private var clearPacketParser = SSHBinaryPacketParser()
    private var clientIdentification: SSHIdentification?
    private var clientProposal: SSHKeyExchangeInitMessage?
    private var encryptedResponsesQueued = false
    private var queuedSendFailureCodes: [POSIXErrorCode] = []
    private var activeReceiveCount = 0
    private var maximumConcurrentReceiveCount = 0
    private var closeCount = 0

    init(
        serverPayloadsAfterNewKeys: [[UInt8]],
        emptyReceiveBehavior: EmptyReceiveBehavior = .endOfStream,
        encryptedChunkSize: Int? = nil,
        receiveDelayNanoseconds: UInt64 = 0
    ) {
        self.serverPayloadsAfterNewKeys = serverPayloadsAfterNewKeys
        self.encryptedChunkSize = encryptedChunkSize
        self.emptyReceiveBehavior = emptyReceiveBehavior
        self.receiveDelayNanoseconds = receiveDelayNanoseconds
        self.receiveChunks = [
            SSHByteStreamChunk(bytes: remoteIdentificationLine, endOfStream: false)
        ]
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        try await self.send(bytes, endOfStream: endOfStream, respectCancellation: true)
    }

    func send(
        _ bytes: [UInt8],
        endOfStream: Bool,
        respectCancellation: Bool
    ) async throws {
        if !self.queuedSendFailureCodes.isEmpty {
            throw POSIXError(self.queuedSendFailureCodes.removeFirst())
        }

        self.sent.append(bytes)
        self.sentEndOfStreamFlags.append(endOfStream)

        if self.clientIdentification == nil, bytes.starts(with: Array("SSH-".utf8)) {
            let identificationLine = String(decoding: bytes, as: UTF8.self)
                .trimmingCharacters(in: .newlines)
            self.clientIdentification = try SSHIdentification(rawValue: identificationLine)
            return
        }

        guard !self.encryptedResponsesQueued else {
            return
        }

        self.clearPacketParser.append(bytes: bytes)
        while let packet = try self.clearPacketParser.nextPacket() {
            let message = try SSHTransportMessageParser().parse(packet.payload)
            switch message {
            case let .keyExchangeInit(localProposal):
                self.clientProposal = localProposal
                try self.queueServerKeyExchangeInit()
            case let .keyExchangeECDHInit(keyExchangeInit):
                try self.queueServerKeyExchangeReply(
                    clientEphemeralPublicKey: keyExchangeInit.publicKey
                )
            case .newKeys:
                try self.queueServerNewKeysAndEncryptedPayloads()
                self.encryptedResponsesQueued = true
            default:
                continue
            }
        }
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        try await self.receive(
            atLeast: minimum,
            atMost: maximum,
            respectCancellation: true
        )
    }

    func receive(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        self.activeReceiveCount += 1
        self.maximumConcurrentReceiveCount = max(
            self.maximumConcurrentReceiveCount,
            self.activeReceiveCount
        )
        defer {
            self.activeReceiveCount -= 1
        }

        if self.receiveDelayNanoseconds > 0 {
            if respectCancellation {
                try await Task.sleep(nanoseconds: self.receiveDelayNanoseconds)
            } else {
                try? await Task.sleep(nanoseconds: self.receiveDelayNanoseconds)
            }
        }

        if self.receiveChunks.isEmpty {
            switch self.emptyReceiveBehavior {
            case .endOfStream:
                return SSHByteStreamChunk(bytes: [], endOfStream: true)
            case let .delayedEndOfStream(delayNanoseconds, ignoreCancellation):
                if ignoreCancellation {
                    try? await Task.sleep(nanoseconds: delayNanoseconds)
                } else {
                    try await Task.sleep(nanoseconds: delayNanoseconds)
                }
                return SSHByteStreamChunk(bytes: [], endOfStream: true)
            case .waitForAppendedChunks:
                while self.receiveChunks.isEmpty {
                    if respectCancellation {
                        try Task.checkCancellation()
                    }
                    await Task.yield()
                }
            }
        }

        return self.receiveChunks.removeFirst()
    }

    func close() async {
        self.closeCount += 1
    }

    func sentPayloads() -> [[UInt8]] {
        self.sent
    }

    func sentPayloadEndOfStreamFlags() -> [Bool] {
        self.sentEndOfStreamFlags
    }

    func remainingReceiveChunkCount() -> Int {
        self.receiveChunks.count
    }

    func enqueueSendFailure(_ code: POSIXErrorCode) {
        self.queuedSendFailureCodes.append(code)
    }

    func maximumConcurrentReceiveCountObserved() -> Int {
        self.maximumConcurrentReceiveCount
    }

    func closeCountObserved() -> Int {
        self.closeCount
    }

    static func fixtureHostKey() -> [UInt8] {
        let hostSigningKey = try! Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(Array(0x01...0x20))
        )
        return Self.makeEd25519Blob(
            bytes: Array(hostSigningKey.publicKey.rawRepresentation)
        )
    }

    private func queueServerKeyExchangeInit() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.remoteProposal)
        )
        let packet = try SSHBinaryPacketSerializer().serialize(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueServerKeyExchangeReply(
        clientEphemeralPublicKey: [UInt8]
    ) throws {
        guard let clientIdentification, let clientProposal else {
            fatalError("client identification and proposal must be available before KEX reply")
        }

        let clientKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(clientProposal)
        )
        let serverKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.remoteProposal)
        )
        let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(clientEphemeralPublicKey)
        )
        let sharedSecretBytes = try self.serverKeyAgreementKey.sharedSecretFromKeyAgreement(
            with: clientEphemeralKey
        ).withUnsafeBytes { Array($0) }
        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let serverEphemeralPublicKey = Array(self.serverKeyAgreementKey.publicKey.rawRepresentation)
        let hostKey = Self.makeEd25519Blob(
            bytes: Array(self.hostSigningKey.publicKey.rawRepresentation)
        )
        let exchangeHash = Self.exchangeHash(
            clientIdentification: clientIdentification,
            serverIdentification: self.remoteIdentification,
            clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
            serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
            serverHostKey: hostKey,
            clientEphemeralPublicKey: clientEphemeralPublicKey,
            serverEphemeralPublicKey: serverEphemeralPublicKey,
            sharedSecret: sharedSecret
        )
        let signature = Self.makeEd25519Blob(
            bytes: Array(try self.hostSigningKey.signature(for: Data(exchangeHash)))
        )
        let replyPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: hostKey,
                    publicKey: serverEphemeralPublicKey,
                    signature: signature
                )
            )
        )
        let replyPacket = try SSHBinaryPacketSerializer().serialize(payload: replyPayload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false)
        )
    }

    private func queueServerNewKeysAndEncryptedPayloads() throws {
        guard let clientProposal else {
            fatalError("client proposal must be available before NEWKEYS")
        }

        let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
            localProposal: clientProposal,
            remoteProposal: self.remoteProposal
        )
        let clientKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(clientProposal)
        )
        let serverKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.remoteProposal)
        )
        guard let keyExchangeInit = self.sent.compactMap({
            try? Self.parseTransportPacket($0)
        }).compactMap({ message -> SSHKeyExchangeECDHInitMessage? in
            guard case let .keyExchangeECDHInit(message) = message else {
                return nil
            }
            return message
        }).last else {
            fatalError("client ECDH init must be sent before NEWKEYS")
        }

        let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(keyExchangeInit.publicKey)
        )
        let sharedSecretBytes = try self.serverKeyAgreementKey.sharedSecretFromKeyAgreement(
            with: clientEphemeralKey
        ).withUnsafeBytes { Array($0) }
        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let hostKey = Self.makeEd25519Blob(
            bytes: Array(self.hostSigningKey.publicKey.rawRepresentation)
        )
        let exchangeHash = Self.exchangeHash(
            clientIdentification: try self.requireClientIdentification(),
            serverIdentification: self.remoteIdentification,
            clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
            serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
            serverHostKey: hostKey,
            clientEphemeralPublicKey: keyExchangeInit.publicKey,
            serverEphemeralPublicKey: Array(self.serverKeyAgreementKey.publicKey.rawRepresentation),
            sharedSecret: sharedSecret
        )
        let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
            negotiatedAlgorithms: negotiation.algorithms,
            sharedSecret: sharedSecret,
            exchangeHash: exchangeHash,
            sessionIdentifier: exchangeHash
        )
        let newKeysPacket = try SSHBinaryPacketSerializer().serialize(
            payload: SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
        )
        var encryptedSerializer = try SSHOutboundEncryptedPacketSerializer(
            negotiatedAlgorithms: negotiation.algorithms,
            keyMaterial: keyMaterial,
            direction: .serverToClient,
            initialSequenceNumber: 3
        )
        let encryptedPackets = try self.serverPayloadsAfterNewKeys.flatMap { payload in
            try encryptedSerializer.serialize(payload: payload)
        }
        let encryptedChunks = makeChunks(
            from: encryptedPackets,
            chunkSize: self.encryptedChunkSize
        )

        if let firstEncryptedChunk = encryptedChunks.first {
            self.receiveChunks.append(
                SSHByteStreamChunk(
                    bytes: newKeysPacket + firstEncryptedChunk,
                    endOfStream: false
                )
            )
            for chunk in encryptedChunks.dropFirst() {
                self.receiveChunks.append(
                    SSHByteStreamChunk(bytes: chunk, endOfStream: false)
                )
            }
        } else {
            self.receiveChunks.append(
                SSHByteStreamChunk(bytes: newKeysPacket, endOfStream: false)
            )
        }
    }

    private func requireClientIdentification() throws -> SSHIdentification {
        guard let clientIdentification else {
            throw SSHTransportError.versionExchangeRequired
        }

        return clientIdentification
    }

    private static func parseTransportPacket(_ bytes: [UInt8]) throws -> SSHTransportMessage? {
        var parser = SSHBinaryPacketParser()
        parser.append(bytes: bytes)
        guard let packet = try parser.nextPacket() else {
            return nil
        }
        return try SSHTransportMessageParser().parse(packet.payload)
    }

    private static func makeEd25519Blob(bytes: [UInt8]) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: "ssh-ed25519")
        writer.write(string: bytes)
        return writer.bytes
    }

    private static func exchangeHash(
        clientIdentification: SSHIdentification,
        serverIdentification: SSHIdentification,
        clientKeyExchangeInitPayload: [UInt8],
        serverKeyExchangeInitPayload: [UInt8],
        serverHostKey: [UInt8],
        clientEphemeralPublicKey: [UInt8],
        serverEphemeralPublicKey: [UInt8],
        sharedSecret: SSHMPInt
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: clientIdentification.rawValue)
        writer.write(utf8: serverIdentification.rawValue)
        writer.write(string: clientKeyExchangeInitPayload)
        writer.write(string: serverKeyExchangeInitPayload)
        writer.write(string: serverHostKey)
        writer.write(string: clientEphemeralPublicKey)
        writer.write(string: serverEphemeralPublicKey)
        writer.write(mpint: sharedSecret)

        let digest = SHA256.hash(data: writer.bytes)
        return Array(digest)
    }
}

enum ServiceRequestRekeyMode: Sendable {
    case remoteInitiated
    case clientInitiated
    case clientInitiatedAfterAuthentication
}

actor ServiceRequestRekeyMockSSHByteStreamTransport: SSHByteStreamTransport {
    private let rekeyMode: ServiceRequestRekeyMode
    private let queuesInitialExtensionInfo: Bool
    private let strictKeyExchange: Bool
    private let channelOpenConfirmationSenderChannel: UInt32?
    private let encryptedPayloadsBeforeClientInitiatedRekeyResponse: [[UInt8]]
    private let remoteIdentificationLine = Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8)
    private let remoteIdentification = try! SSHIdentification(
        rawValue: "SSH-2.0-OpenSSH_9.9 test"
    )
    private let initialRemoteProposal: SSHKeyExchangeInitMessage
    private let rekeyRemoteProposal: SSHKeyExchangeInitMessage
    private let hostSigningKey = try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(Array(0x01...0x20))
    )
    private let initialServerKeyAgreementKey = try! Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )
    private let rekeyServerKeyAgreementKey = try! Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x41...0x60))
    )

    private var receiveChunks: [SSHByteStreamChunk]
    private var sent: [[UInt8]] = []
    private var clearPacketParser = SSHBinaryPacketParser()
    private var encryptedPacketParser: SSHInboundEncryptedPacketParser?
    private var serverEncryptedPacketSerializer: SSHOutboundEncryptedPacketSerializer?
    private var serverEncryptedSequenceNumber: UInt32 = 0
    private var clientEncryptedSequenceNumber: UInt32 = 0
    private var clientIdentification: SSHIdentification?
    private var initialClientProposal: SSHKeyExchangeInitMessage?
    private var initialNegotiation: SSHKeyExchangeInitNegotiation?
    private var initialSessionIdentifier: [UInt8]?
    private var rekeyClientProposalValue: SSHKeyExchangeInitMessage?
    private var rekeyNegotiation: SSHKeyExchangeInitNegotiation?
    private var rekeyTransportKeyMaterial: SSHTransportKeyMaterial?
    private var hasPendingServiceAccept = false
    private var didStartRekey = false
    private var didCompleteRekey = false
    private var didAuthenticate = false

    init(
        rekeyMode: ServiceRequestRekeyMode,
        queuesInitialExtensionInfo: Bool = false,
        strictKeyExchange: Bool = false,
        channelOpenConfirmationSenderChannel: UInt32? = nil,
        encryptedPayloadsBeforeClientInitiatedRekeyResponse: [[UInt8]] = []
    ) {
        self.rekeyMode = rekeyMode
        self.queuesInitialExtensionInfo = queuesInitialExtensionInfo
        self.strictKeyExchange = strictKeyExchange
        self.channelOpenConfirmationSenderChannel = channelOpenConfirmationSenderChannel
        self.encryptedPayloadsBeforeClientInitiatedRekeyResponse =
            encryptedPayloadsBeforeClientInitiatedRekeyResponse
        self.initialRemoteProposal = try! SSHKeyExchangeInitMessage(
            cookie: Array(0x10...0x1f),
            keyExchangeAlgorithms: strictKeyExchange
                ? ["curve25519-sha256", "kex-strict-s-v00@openssh.com"]
                : ["curve25519-sha256"],
            serverHostKeyAlgorithms: ["ssh-ed25519"],
            encryptionAlgorithmsClientToServer: ["aes128-ctr"],
            encryptionAlgorithmsServerToClient: ["aes128-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"]
        )
        self.rekeyRemoteProposal = try! SSHKeyExchangeInitMessage(
            cookie: Array(0x30...0x3f),
            keyExchangeAlgorithms: ["curve25519-sha256"],
            serverHostKeyAlgorithms: ["ssh-ed25519"],
            encryptionAlgorithmsClientToServer: ["aes128-ctr"],
            encryptionAlgorithmsServerToClient: ["aes128-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"]
        )
        self.receiveChunks = [
            SSHByteStreamChunk(bytes: self.remoteIdentificationLine, endOfStream: false)
        ]
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        self.sent.append(bytes)

        if self.clientIdentification == nil, bytes.starts(with: Array("SSH-".utf8)) {
            let identificationLine = String(decoding: bytes, as: UTF8.self)
                .trimmingCharacters(in: .newlines)
            self.clientIdentification = try SSHIdentification(rawValue: identificationLine)
            return
        }

        if var encryptedPacketParser = self.encryptedPacketParser {
            encryptedPacketParser.append(bytes: bytes)
            while let packet = try encryptedPacketParser.nextPacket() {
                self.clientEncryptedSequenceNumber &+= 1
                self.encryptedPacketParser = encryptedPacketParser
                try self.handleEncryptedClientPayload(packet.payload)
                encryptedPacketParser = self.encryptedPacketParser ?? encryptedPacketParser
            }
            self.encryptedPacketParser = encryptedPacketParser
            return
        }

        self.clearPacketParser.append(bytes: bytes)
        while let packet = try self.clearPacketParser.nextPacket() {
            let message = try SSHTransportMessageParser().parse(packet.payload)
            try self.handleClearClientTransportMessage(message)
        }
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        if self.receiveChunks.isEmpty {
            return SSHByteStreamChunk(bytes: [], endOfStream: true)
        }

        return self.receiveChunks.removeFirst()
    }

    func rekeyClientProposal() -> SSHKeyExchangeInitMessage? {
        self.rekeyClientProposalValue
    }

    private func handleClearClientTransportMessage(_ message: SSHTransportMessage) throws {
        switch message {
        case let .keyExchangeInit(localProposal):
            self.initialClientProposal = localProposal
            try self.queueInitialServerKeyExchangeInit()
        case let .keyExchangeECDHInit(keyExchangeInit):
            try self.queueInitialServerKeyExchangeReply(
                clientEphemeralPublicKey: keyExchangeInit.publicKey
            )
        case .newKeys:
            try self.queueInitialServerNewKeys()
            try self.installInitialEncryptedState()
            if self.queuesInitialExtensionInfo {
                try self.queueInitialExtensionInfo()
            }
        default:
            break
        }
    }

    private func handleEncryptedClientTransportMessage(_ message: SSHTransportMessage) throws {
        switch message {
        case let .serviceRequest(request):
            guard request.serviceName == "ssh-userauth" else {
                return
            }
            self.hasPendingServiceAccept = true
            switch self.rekeyMode {
            case .remoteInitiated:
                guard !self.didStartRekey else {
                    return
                }
                try self.queueRemoteRekeyInit()
                self.didStartRekey = true
            case .clientInitiated:
                if self.didCompleteRekey {
                    try self.queueEncryptedServiceAccept()
                    self.hasPendingServiceAccept = false
                }
            case .clientInitiatedAfterAuthentication:
                try self.queueEncryptedServiceAccept()
                self.hasPendingServiceAccept = false
            }
        case let .keyExchangeInit(localProposal):
            self.rekeyClientProposalValue = localProposal
            if (self.rekeyMode == .clientInitiated
                || self.rekeyMode == .clientInitiatedAfterAuthentication),
               !self.didStartRekey {
                try self.queueEncryptedPayloads(
                    self.encryptedPayloadsBeforeClientInitiatedRekeyResponse
                )
                try self.queueRemoteRekeyInit()
                self.didStartRekey = true
            }
        case let .keyExchangeECDHInit(keyExchangeInit):
            try self.queueRemoteRekeyReply(
                clientEphemeralPublicKey: keyExchangeInit.publicKey
            )
        case .newKeys:
            switch self.rekeyMode {
            case .remoteInitiated:
                try self.queueRemoteRekeyNewKeysAndServiceAccept()
            case .clientInitiated, .clientInitiatedAfterAuthentication:
                try self.queueRemoteRekeyNewKeys()
                try self.installRekeyEncryptedState()
                self.didCompleteRekey = true
                if self.hasPendingServiceAccept {
                    try self.queueEncryptedServiceAccept()
                    self.hasPendingServiceAccept = false
                }
            }
        default:
            break
        }
    }

    private func handleEncryptedClientPayload(_ payload: [UInt8]) throws {
        guard let messageID = payload.first else {
            return
        }

        if SSHTransportMessageID(rawValue: messageID) != nil {
            let message = try SSHTransportMessageParser().parse(payload)
            try self.handleEncryptedClientTransportMessage(message)
            return
        }

        if SSHConnectionMessageID(rawValue: messageID) != nil {
            let message = try SSHConnectionMessageParser().parse(payload)
            try self.handleEncryptedClientConnectionMessage(message)
            return
        }

        guard let authMessageID = SSHUserAuthenticationMessageID(rawValue: messageID) else {
            return
        }

        switch authMessageID {
        case .request:
            guard self.rekeyMode == .clientInitiatedAfterAuthentication,
                  !self.didAuthenticate else {
                return
            }
            try self.queueEncryptedAuthenticationSuccess()
            self.didAuthenticate = true
        default:
            break
        }
    }

    private func handleEncryptedClientConnectionMessage(
        _ message: SSHConnectionMessage
    ) throws {
        guard let channelOpenConfirmationSenderChannel else {
            return
        }

        switch message {
        case let .channelOpen(open):
            let payload = try SSHConnectionMessageSerializer().serialize(
                .channelOpenConfirmation(
                    SSHChannelOpenConfirmationMessage(
                        recipientChannel: open.senderChannel,
                        senderChannel: channelOpenConfirmationSenderChannel,
                        initialWindowSize: 1_048_576,
                        maximumPacketSize: 32_768,
                        channelTypeData: []
                    )
                )
            )
            try self.queueEncryptedPayloads([payload])
        default:
            return
        }
    }

    private func queueInitialServerKeyExchangeInit() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.initialRemoteProposal)
        )
        let packet = try SSHBinaryPacketSerializer().serialize(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueInitialServerKeyExchangeReply(
        clientEphemeralPublicKey: [UInt8]
    ) throws {
        guard let clientIdentification,
              let initialClientProposal else {
            fatalError("client identification and proposal must be available before KEX reply")
        }

        let initialNegotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
            localProposal: initialClientProposal,
            remoteProposal: self.initialRemoteProposal
        )
        let clientKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(initialClientProposal)
        )
        let serverKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.initialRemoteProposal)
        )
        let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(clientEphemeralPublicKey)
        )
        let sharedSecretBytes = try self.initialServerKeyAgreementKey.sharedSecretFromKeyAgreement(
            with: clientEphemeralKey
        ).withUnsafeBytes { Array($0) }
        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let hostKey = Self.makeEd25519Blob(
            bytes: Array(self.hostSigningKey.publicKey.rawRepresentation)
        )
        let exchangeHash = Self.exchangeHash(
            clientIdentification: clientIdentification,
            serverIdentification: self.remoteIdentification,
            clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
            serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
            serverHostKey: hostKey,
            clientEphemeralPublicKey: clientEphemeralPublicKey,
            serverEphemeralPublicKey: Array(self.initialServerKeyAgreementKey.publicKey.rawRepresentation),
            sharedSecret: sharedSecret
        )
        let signature = Self.makeEd25519Blob(
            bytes: Array(try self.hostSigningKey.signature(for: Data(exchangeHash)))
        )
        let replyPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: hostKey,
                    publicKey: Array(self.initialServerKeyAgreementKey.publicKey.rawRepresentation),
                    signature: signature
                )
            )
        )
        let replyPacket = try SSHBinaryPacketSerializer().serialize(payload: replyPayload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false)
        )

        self.initialNegotiation = initialNegotiation
        self.initialSessionIdentifier = exchangeHash
    }

    private func queueInitialServerNewKeys() throws {
        let packet = try SSHBinaryPacketSerializer().serialize(
            payload: SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
        )
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueInitialExtensionInfo() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .extensionInfo(
                SSHExtensionInfoMessage(
                    entries: [
                        SSHExtensionInfoEntry(
                            name: "server-sig-algs",
                            value: Array("ssh-ed25519".utf8)
                        )
                    ]
                )
            )
        )
        let packet = try self.serializeServerEncryptedPacket(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func installInitialEncryptedState() throws {
        guard let initialNegotiation,
              let initialSessionIdentifier,
              let clientEphemeralPublicKey = self.sent.compactMap({
                  try? Self.parseTransportPacket($0)
              }).compactMap({ message -> SSHKeyExchangeECDHInitMessage? in
                  guard case let .keyExchangeECDHInit(message) = message else {
                      return nil
                  }
                  return message
              }).last else {
            fatalError("initial key exchange transcript must be available before encrypted state")
        }

        let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(clientEphemeralPublicKey.publicKey)
        )
        let sharedSecretBytes = try self.initialServerKeyAgreementKey.sharedSecretFromKeyAgreement(
            with: clientEphemeralKey
        ).withUnsafeBytes { Array($0) }
        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
            negotiatedAlgorithms: initialNegotiation.algorithms,
            sharedSecret: sharedSecret,
            exchangeHash: initialSessionIdentifier,
            sessionIdentifier: initialSessionIdentifier
        )

        self.encryptedPacketParser = try SSHInboundEncryptedPacketParser(
            negotiatedAlgorithms: initialNegotiation.algorithms,
            keyMaterial: keyMaterial,
            direction: .clientToServer,
            initialSequenceNumber: self.strictKeyExchange ? 0 : 3
        )
        self.serverEncryptedPacketSerializer = try SSHOutboundEncryptedPacketSerializer(
            negotiatedAlgorithms: initialNegotiation.algorithms,
            keyMaterial: keyMaterial,
            direction: .serverToClient,
            initialSequenceNumber: self.strictKeyExchange ? 0 : 3
        )
        self.serverEncryptedSequenceNumber = self.strictKeyExchange ? 0 : 3
        self.clientEncryptedSequenceNumber = self.strictKeyExchange ? 0 : 3
    }

    private func queueRemoteRekeyInit() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.rekeyRemoteProposal)
        )
        let packet = try self.serializeServerEncryptedPacket(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueRemoteRekeyReply(
        clientEphemeralPublicKey: [UInt8]
    ) throws {
        guard let initialSessionIdentifier,
              let rekeyClientProposal = self.rekeyClientProposalValue else {
            fatalError("rekey proposal and session identifier must be available before reply")
        }

        let rekeyNegotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
            localProposal: rekeyClientProposal,
            remoteProposal: self.rekeyRemoteProposal
        )
        let clientKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(rekeyClientProposal)
        )
        let serverKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(self.rekeyRemoteProposal)
        )
        let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(clientEphemeralPublicKey)
        )
        let sharedSecretBytes = try self.rekeyServerKeyAgreementKey.sharedSecretFromKeyAgreement(
            with: clientEphemeralKey
        ).withUnsafeBytes { Array($0) }
        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let hostKey = Self.makeEd25519Blob(
            bytes: Array(self.hostSigningKey.publicKey.rawRepresentation)
        )
        let exchangeHash = Self.exchangeHash(
            clientIdentification: try self.requireClientIdentification(),
            serverIdentification: self.remoteIdentification,
            clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
            serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
            serverHostKey: hostKey,
            clientEphemeralPublicKey: clientEphemeralPublicKey,
            serverEphemeralPublicKey: Array(self.rekeyServerKeyAgreementKey.publicKey.rawRepresentation),
            sharedSecret: sharedSecret
        )
        let signature = Self.makeEd25519Blob(
            bytes: Array(try self.hostSigningKey.signature(for: Data(exchangeHash)))
        )
        let replyPayload = try SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: hostKey,
                    publicKey: Array(self.rekeyServerKeyAgreementKey.publicKey.rawRepresentation),
                    signature: signature
                )
            )
        )
        let replyPacket = try self.serializeServerEncryptedPacket(payload: replyPayload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false)
        )

        self.rekeyTransportKeyMaterial = try SSHTransportKeyDeriver().deriveKeys(
            negotiatedAlgorithms: rekeyNegotiation.algorithms,
            sharedSecret: sharedSecret,
            exchangeHash: exchangeHash,
            sessionIdentifier: initialSessionIdentifier
        )
        self.rekeyNegotiation = rekeyNegotiation
    }

    private func queueRemoteRekeyNewKeysAndServiceAccept() throws {
        guard let rekeyNegotiation,
              let rekeyTransportKeyMaterial else {
            fatalError("rekey transport material must be available before NEWKEYS")
        }

        let newKeysPayload = try SSHTransportMessageSerializer().serialize(
            .newKeys(SSHNewKeysMessage())
        )
        let newKeysPacket = try self.serializeServerEncryptedPacket(payload: newKeysPayload)
        if self.strictKeyExchange {
            self.serverEncryptedSequenceNumber = 0
            self.clientEncryptedSequenceNumber = 0
        }
        var postRekeySerializer = try SSHOutboundEncryptedPacketSerializer(
            negotiatedAlgorithms: rekeyNegotiation.algorithms,
            keyMaterial: rekeyTransportKeyMaterial,
            direction: .serverToClient,
            initialSequenceNumber: self.serverEncryptedSequenceNumber
        )
        let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
        let serviceAcceptPacket = try postRekeySerializer.serialize(payload: serviceAcceptPayload)
        self.serverEncryptedPacketSerializer = postRekeySerializer
        self.serverEncryptedSequenceNumber &+= 1
        try self.installRekeyEncryptedInboundState()
        self.didCompleteRekey = true
        self.hasPendingServiceAccept = false

        self.receiveChunks.append(
            SSHByteStreamChunk(
                bytes: newKeysPacket + serviceAcceptPacket,
                endOfStream: false
            )
        )
    }

    private func queueRemoteRekeyNewKeys() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .newKeys(SSHNewKeysMessage())
        )
        let packet = try self.serializeServerEncryptedPacket(payload: payload)
        if self.strictKeyExchange {
            self.serverEncryptedSequenceNumber = 0
            self.clientEncryptedSequenceNumber = 0
        }
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func installRekeyEncryptedState() throws {
        guard let rekeyNegotiation,
              let rekeyTransportKeyMaterial else {
            fatalError("rekey transport material must be available before rekey state install")
        }

        self.serverEncryptedPacketSerializer = try SSHOutboundEncryptedPacketSerializer(
            negotiatedAlgorithms: rekeyNegotiation.algorithms,
            keyMaterial: rekeyTransportKeyMaterial,
            direction: .serverToClient,
            initialSequenceNumber: self.serverEncryptedSequenceNumber
        )
        try self.installRekeyEncryptedInboundState()
    }

    private func installRekeyEncryptedInboundState() throws {
        guard let rekeyNegotiation,
              let rekeyTransportKeyMaterial else {
            fatalError("rekey transport material must be available before rekey parser install")
        }

        self.encryptedPacketParser = try SSHInboundEncryptedPacketParser(
            negotiatedAlgorithms: rekeyNegotiation.algorithms,
            keyMaterial: rekeyTransportKeyMaterial,
            direction: .clientToServer,
            initialSequenceNumber: self.clientEncryptedSequenceNumber
        )
    }

    private func queueEncryptedServiceAccept() throws {
        let payload = try SSHTransportMessageSerializer().serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
        let packet = try self.serializeServerEncryptedPacket(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueEncryptedAuthenticationSuccess() throws {
        let payload = try SSHUserAuthenticationMessageSerializer().serialize(
            .success(SSHUserAuthenticationSuccessMessage())
        )
        let packet = try self.serializeServerEncryptedPacket(payload: payload)
        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packet, endOfStream: false)
        )
    }

    private func queueEncryptedPayloads(_ payloads: [[UInt8]]) throws {
        let packets = try self.serializeServerEncryptedPackets(payloads: payloads)
        guard !packets.isEmpty else {
            return
        }

        self.receiveChunks.append(
            SSHByteStreamChunk(bytes: packets, endOfStream: false)
        )
    }

    private func serializeServerEncryptedPackets(payloads: [[UInt8]]) throws -> [UInt8] {
        try payloads.flatMap { payload in
            try self.serializeServerEncryptedPacket(payload: payload)
        }
    }

    private func serializeServerEncryptedPacket(payload: [UInt8]) throws -> [UInt8] {
        guard var serverEncryptedPacketSerializer = self.serverEncryptedPacketSerializer else {
            fatalError("encrypted serializer must be installed before encrypted payloads")
        }

        let packet = try serverEncryptedPacketSerializer.serialize(payload: payload)
        self.serverEncryptedPacketSerializer = serverEncryptedPacketSerializer
        self.serverEncryptedSequenceNumber &+= 1
        return packet
    }

    private func requireClientIdentification() throws -> SSHIdentification {
        guard let clientIdentification else {
            throw SSHTransportError.versionExchangeRequired
        }

        return clientIdentification
    }

    private static func parseTransportPacket(_ bytes: [UInt8]) throws -> SSHTransportMessage? {
        var parser = SSHBinaryPacketParser()
        parser.append(bytes: bytes)
        guard let packet = try parser.nextPacket() else {
            return nil
        }
        return try SSHTransportMessageParser().parse(packet.payload)
    }

    private static func makeEd25519Blob(bytes: [UInt8]) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: "ssh-ed25519")
        writer.write(string: bytes)
        return writer.bytes
    }

    private static func exchangeHash(
        clientIdentification: SSHIdentification,
        serverIdentification: SSHIdentification,
        clientKeyExchangeInitPayload: [UInt8],
        serverKeyExchangeInitPayload: [UInt8],
        serverHostKey: [UInt8],
        clientEphemeralPublicKey: [UInt8],
        serverEphemeralPublicKey: [UInt8],
        sharedSecret: SSHMPInt
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: clientIdentification.rawValue)
        writer.write(utf8: serverIdentification.rawValue)
        writer.write(string: clientKeyExchangeInitPayload)
        writer.write(string: serverKeyExchangeInitPayload)
        writer.write(string: serverHostKey)
        writer.write(string: clientEphemeralPublicKey)
        writer.write(string: serverEphemeralPublicKey)
        writer.write(mpint: sharedSecret)

        let digest = SHA256.hash(data: writer.bytes)
        return Array(digest)
    }
}

func makeConnectionFixtureTransport(
    serverPayloadsAfterNewKeys: [[UInt8]],
    encryptedChunkSize: Int? = nil
) throws -> any SSHByteStreamTransport {
    ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: serverPayloadsAfterNewKeys,
        encryptedChunkSize: encryptedChunkSize
    )
}

func makeConnectionFixtureClientToServerDecryptionContext(
    sentPayloads: [[UInt8]]
) throws -> (
    algorithms: SSHNegotiatedAlgorithms,
    keyMaterial: SSHTransportKeyMaterial
) {
    let remoteIdentification = try SSHIdentification(
        rawValue: "SSH-2.0-OpenSSH_9.9 test"
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let hostSigningKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(Array(0x01...0x20))
    )
    let serverKeyAgreementKey = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )

    guard let identificationPayload = sentPayloads.first else {
        throw SSHTransportError.versionExchangeRequired
    }
    let clientIdentificationLine = String(
        decoding: identificationPayload,
        as: UTF8.self
    ).trimmingCharacters(in: .newlines)
    let clientIdentification = try SSHIdentification(rawValue: clientIdentificationLine)

    var clearPacketParser = SSHBinaryPacketParser()
    clearPacketParser.append(bytes: Array(sentPayloads.dropFirst().joined()))

    var clientProposal: SSHKeyExchangeInitMessage?
    var clientECDHInit: SSHKeyExchangeECDHInitMessage?

    while let packet = try clearPacketParser.nextPacket() {
        let message = try SSHTransportMessageParser().parse(packet.payload)
        switch message {
        case let .keyExchangeInit(value):
            clientProposal = value
        case let .keyExchangeECDHInit(value):
            clientECDHInit = value
        case .newKeys:
            break
        default:
            continue
        }

        if clientProposal != nil, clientECDHInit != nil {
            break
        }
    }

    guard let clientProposal, let clientECDHInit else {
        throw SSHTransportError.endOfStreamBeforePacket
    }

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: clientProposal,
        remoteProposal: remoteProposal
    )
    let clientKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
        .keyExchangeInit(clientProposal)
    )
    let serverKeyExchangeInitPayload = try SSHTransportMessageSerializer().serialize(
        .keyExchangeInit(remoteProposal)
    )
    let clientEphemeralKey = try Curve25519.KeyAgreement.PublicKey(
        rawRepresentation: Data(clientECDHInit.publicKey)
    )
    let sharedSecretBytes = try serverKeyAgreementKey.sharedSecretFromKeyAgreement(
        with: clientEphemeralKey
    ).withUnsafeBytes { Array($0) }
    let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
    let hostKey = makeFixtureEd25519Blob(
        bytes: Array(hostSigningKey.publicKey.rawRepresentation)
    )
    let exchangeHash = makeConnectionFixtureExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: remoteIdentification,
        clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
        serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
        serverHostKey: hostKey,
        clientEphemeralPublicKey: clientECDHInit.publicKey,
        serverEphemeralPublicKey: Array(serverKeyAgreementKey.publicKey.rawRepresentation),
        sharedSecret: sharedSecret
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiation.algorithms,
        sharedSecret: sharedSecret,
        exchangeHash: exchangeHash,
        sessionIdentifier: exchangeHash
    )

    return (negotiation.algorithms, keyMaterial)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func makeActivatedTransportFixture(
    serverPayloadsAfterNewKeys: [[UInt8]],
    remoteIdentificationRawValue: String = "SSH-2.0-OpenSSH_9.9 test",
    encryptedChunkSize: Int? = nil,
    emptyReceiveBehavior: EmptyReceiveBehavior = .endOfStream,
    receiveDelayNanoseconds: UInt64 = 0,
    sendDelayNanoseconds: UInt64 = 0,
    strictKeyExchange: Bool = false,
    compressionAlgorithmClientToServer: String = "none",
    compressionAlgorithmServerToClient: String = "none",
    automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
    keepalivePolicy: SSHTransportKeepalivePolicy = .disabled
) async throws -> (
    client: SSHTransportProtocolClient,
    transport: ProtocolClientMockSSHByteStreamTransport,
    activation: SSHCurve25519TransportActivation
) {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: strictKeyExchange
            ? ["curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"]
            : ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: [compressionAlgorithmClientToServer],
        compressionAlgorithmsServerToClient: [compressionAlgorithmServerToClient]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: strictKeyExchange
            ? ["curve25519-sha256", "kex-strict-s-v00@openssh.com"]
            : ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: [compressionAlgorithmClientToServer],
        compressionAlgorithmsServerToClient: [compressionAlgorithmServerToClient]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let exchangeHash = Array(0x70...0x8f).map(UInt8.init)
    let signingKey = Curve25519.Signing.PrivateKey()
    var hostKeyWriter = SSHWireWriter()
    hostKeyWriter.write(utf8: "ssh-ed25519")
    hostKeyWriter.write(string: Array(signingKey.publicKey.rawRepresentation))
    var signatureWriter = SSHWireWriter()
    signatureWriter.write(utf8: "ssh-ed25519")
    signatureWriter.write(
        string: try Array(signingKey.signature(for: Data(exchangeHash)))
    )
    let keyExchangeResult = SSHCurve25519ClientKeyExchangeResult(
        keyExchangeAlgorithm: "curve25519-sha256",
        clientEphemeralPublicKey: Array(repeating: 0x33, count: 32),
        serverHostKey: hostKeyWriter.bytes,
        serverEphemeralPublicKey: Array(repeating: 0x44, count: 32),
        serverSignature: signatureWriter.bytes,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: exchangeHash,
        sessionIdentifier: exchangeHash
    )
    let keyMaterial = try keyExchangeResult.deriveTransportKeyMaterial(
        negotiatedAlgorithms: negotiation.algorithms
    )
    let clearNewKeysPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
    )
    var encryptedSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiation.algorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: strictKeyExchange ? 0 : 1
    )
    let encryptedPackets = try serverPayloadsAfterNewKeys.flatMap { payload in
        try encryptedSerializer.serialize(payload: payload)
    }
    let encryptedChunks = makeChunks(
        from: encryptedPackets,
        chunkSize: encryptedChunkSize
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("\(remoteIdentificationRawValue)\r\n".utf8),
                endOfStream: false
            ),
        ] + encryptedChunks.enumerated().map { index, chunk in
            SSHByteStreamChunk(
                bytes: index == 0 ? clearNewKeysPacket + chunk : chunk,
                endOfStream: false
            )
        },
        emptyReceiveBehavior: emptyReceiveBehavior,
        receiveDelayNanoseconds: receiveDelayNanoseconds,
        sendDelayNanoseconds: sendDelayNanoseconds
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        automaticRekeyPolicy: automaticRekeyPolicy,
        keepalivePolicy: keepalivePolicy
    )

    _ = try await client.exchangeIdentifications()
    let activation = try await client.activateCurve25519Transport(
        negotiation: negotiation,
        keyExchangeResult: keyExchangeResult,
        hostKeyTrustPolicy: .acceptAnyVerifiedHostKey
    )

    return (client, transport, activation)
}

func parseSFTPMessage(from packet: SSHBinaryPacket) throws -> SSHSFTPMessage {
    let channelData = try #require({
        let message = try SSHConnectionMessageParser().parse(packet.payload)
        if case let .channelData(value) = message {
            return value
        }
        return nil
    }())
    let payload = try #require({
        var packetParser = SSHSFTPPacketParser()
        packetParser.append(bytes: channelData.data)
        return try packetParser.nextPayload()
    }())
    return try SSHSFTPMessageParser().parse(payload)
}

func makeChunks(from bytes: [UInt8], chunkSize: Int?) -> [[UInt8]] {
    guard let chunkSize, chunkSize > 0 else {
        return [bytes]
    }

    guard !bytes.isEmpty else {
        return [[]]
    }

    var chunks: [[UInt8]] = []
    chunks.reserveCapacity((bytes.count + chunkSize - 1) / chunkSize)

    var startIndex = 0
    while startIndex < bytes.count {
        let endIndex = min(startIndex + chunkSize, bytes.count)
        chunks.append(Array(bytes[startIndex..<endIndex]))
        startIndex = endIndex
    }

    return chunks
}

func expectOperationCancellation(
    after delayNanoseconds: UInt64 = 50_000_000,
    _ operation: @escaping @Sendable () async throws -> Void
) async {
    let task = Task(operation: operation)

    try? await Task.sleep(nanoseconds: delayNanoseconds)
    task.cancel()

    do {
        try await task.value
        Issue.record("Expected operation cancellation")
    } catch {
        #expect(error is CancellationError)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func waitForSentPayloadCount(
    on transport: ProtocolClientMockSSHByteStreamTransport,
    minimumCount: Int,
    maxAttempts: Int = 200,
    sleepNanoseconds: UInt64 = 0
) async -> Bool {
    for _ in 0..<maxAttempts {
        if await transport.sentPayloads().count >= minimumCount {
            return true
        }
        if sleepNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: sleepNanoseconds)
        }
        await Task.yield()
    }

    return false
}

func waitForSentPayloadCount(
    on transport: ConnectionFixtureMockSSHByteStreamTransport,
    minimumCount: Int,
    maxAttempts: Int = 200,
    sleepNanoseconds: UInt64 = 0
) async -> Bool {
    for _ in 0..<maxAttempts {
        if await transport.sentPayloads().count >= minimumCount {
            return true
        }
        if sleepNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: sleepNanoseconds)
        }
        await Task.yield()
    }

    return false
}

func waitUntil(
    maxAttempts: Int = 200,
    sleepNanoseconds: UInt64 = 0,
    _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
    for _ in 0..<maxAttempts {
        if await predicate() {
            return true
        }
        if sleepNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: sleepNanoseconds)
        }
        await Task.yield()
    }

    return false
}

private func makeFixtureEd25519Blob(bytes: [UInt8]) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: "ssh-ed25519")
    writer.write(string: bytes)
    return writer.bytes
}

private func makeConnectionFixtureExchangeHash(
    clientIdentification: SSHIdentification,
    serverIdentification: SSHIdentification,
    clientKeyExchangeInitPayload: [UInt8],
    serverKeyExchangeInitPayload: [UInt8],
    serverHostKey: [UInt8],
    clientEphemeralPublicKey: [UInt8],
    serverEphemeralPublicKey: [UInt8],
    sharedSecret: SSHMPInt
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: clientIdentification.rawValue)
    writer.write(utf8: serverIdentification.rawValue)
    writer.write(string: clientKeyExchangeInitPayload)
    writer.write(string: serverKeyExchangeInitPayload)
    writer.write(string: serverHostKey)
    writer.write(string: clientEphemeralPublicKey)
    writer.write(string: serverEphemeralPublicKey)
    writer.write(mpint: sharedSecret)

    let digest = SHA256.hash(data: writer.bytes)
    return Array(digest)
}
