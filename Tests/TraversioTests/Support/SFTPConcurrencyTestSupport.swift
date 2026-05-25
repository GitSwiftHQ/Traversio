// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
@testable import Traversio

actor SFTPTransferProgressRecorder {
    private var values: [SSHSFTPTransferProgress] = []

    func record(_ value: SSHSFTPTransferProgress) {
        self.values.append(value)
    }

    func snapshot() -> [SSHSFTPTransferProgress] {
        self.values
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
typealias ConcurrentSFTPFixture = (
    client: SSHTransportProtocolClient,
    transport: ProtocolClientMockSSHByteStreamTransport,
    activation: SSHCurve25519TransportActivation,
    server: ConcurrentSFTPServer
)

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func makeConcurrentSFTPFixture(
    senderChannel: UInt32,
    sftpMessagesAfterVersion: [SSHSFTPMessage] = [],
    initialWindowSize: UInt32 = 256,
    maximumPacketSize: UInt32 = 128
) async throws -> ConcurrentSFTPFixture {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: senderChannel,
                initialWindowSize: initialWindowSize,
                maximumPacketSize: maximumPacketSize,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(
                SSHSFTPVersionMessage(
                    version: 3,
                    extensions: []
                )
            )
        )
    )
    let versionPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: versionPacket
            )
        )
    )
    let extraPayloads = try sftpMessagesAfterVersion.map(makeConcurrentSFTPChannelDataPayload(_:))
    let serverPayloadsAfterNewKeys = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        channelSuccessPayload,
        versionPayload,
    ] + extraPayloads

    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
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
    var serverSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiation.algorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    let encryptedPackets = try serverPayloadsAfterNewKeys.flatMap { payload in
        try serverSerializer.serialize(payload: payload)
    }
    let encryptedChunks = makeChunks(from: encryptedPackets, chunkSize: nil)
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
        ] + encryptedChunks.enumerated().map { index, chunk in
            SSHByteStreamChunk(
                bytes: index == 0 ? clearNewKeysPacket + chunk : chunk,
                endOfStream: false
            )
        },
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()
    let activation = try await client.activateCurve25519Transport(
        negotiation: negotiation,
        keyExchangeResult: keyExchangeResult,
        hostKeyTrustPolicy: .acceptAnyVerifiedHostKey
    )

    return (
        client: client,
        transport: transport,
        activation: activation,
        server: ConcurrentSFTPServer(
            transport: transport,
            serializer: serverSerializer
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func waitForSentSFTPMessages(
    minimumCount: Int,
    from fixture: ConcurrentSFTPFixture
) async throws -> [SSHSFTPMessage] {
    for _ in 0..<500 {
        let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
        if sentMessages.count >= minimumCount {
            return sentMessages
        }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }

    return try await extractConcurrentSentSFTPMessages(from: fixture)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func extractConcurrentSentSFTPMessages(
    from fixture: ConcurrentSFTPFixture
) async throws -> [SSHSFTPMessage] {
    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    var sftpPacketParser = SSHSFTPPacketParser()
    var messages: [SSHSFTPMessage] = []
    let connectionMessageParser = SSHConnectionMessageParser()

    for packet in packets.dropFirst(5) {
        let message = try connectionMessageParser.parse(packet.payload)
        guard case let .channelData(channelData) = message else {
            continue
        }
        sftpPacketParser.append(bytes: channelData.data)
        while let payload = try sftpPacketParser.nextPayload() {
            messages.append(try SSHSFTPMessageParser().parse(payload))
        }
    }

    return messages
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func makeConcurrentSFTPChannelDataPayload(_ message: SSHSFTPMessage) throws -> [UInt8] {
    let packet = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(message)
    )
    return try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: packet
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
actor ConcurrentSFTPServer {
    private let transport: ProtocolClientMockSSHByteStreamTransport
    private var serializer: SSHOutboundEncryptedPacketSerializer

    init(
        transport: ProtocolClientMockSSHByteStreamTransport,
        serializer: SSHOutboundEncryptedPacketSerializer
    ) {
        self.transport = transport
        self.serializer = serializer
    }

    func appendSFTPMessages(_ messages: [SSHSFTPMessage]) async throws {
        let payloads = try messages.map(makeConcurrentSFTPChannelDataPayload(_:))
        let encryptedPackets = try payloads.flatMap { payload in
            try self.serializer.serialize(payload: payload)
        }
        let encryptedChunks = makeChunks(from: encryptedPackets, chunkSize: nil).map { bytes in
            SSHByteStreamChunk(bytes: bytes, endOfStream: false)
        }
        await self.transport.appendReceiveChunks(encryptedChunks)
    }
}

func firstStatRequestID(in messages: [SSHSFTPMessage]) -> UInt32? {
    for message in messages {
        if case let .stat(statMessage) = message {
            return statMessage.requestID
        }
    }

    return nil
}

func firstReadLinkRequestID(in messages: [SSHSFTPMessage]) -> UInt32? {
    for message in messages {
        if case let .readLink(readLinkMessage) = message {
            return readLinkMessage.requestID
        }
    }

    return nil
}
