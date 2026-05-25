// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

actor MockLocalPortForwardTransport: SSHByteStreamTransport {
    struct SentEvent: Equatable, Sendable {
        let bytes: [UInt8]
        let endOfStream: Bool
    }

    private var receiveChunks: [SSHByteStreamChunk]
    private var sentEvents: [SentEvent] = []
    private let terminalSendError: (any Error)?

    init(
        receiveChunks: [SSHByteStreamChunk],
        terminalSendError: (any Error)? = nil
    ) {
        self.receiveChunks = receiveChunks
        self.terminalSendError = terminalSendError
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        if endOfStream, let terminalSendError {
            throw terminalSendError
        }
        self.sentEvents.append(SentEvent(bytes: bytes, endOfStream: endOfStream))
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        if self.receiveChunks.isEmpty {
            return SSHByteStreamChunk(bytes: [], endOfStream: true)
        }

        return self.receiveChunks.removeFirst()
    }

    func recordedSentEvents() -> [SentEvent] {
        self.sentEvents
    }
}

private let operationCanceledNSError = NSError(
    domain: NSPOSIXErrorDomain,
    code: 89
)

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpipChannelByteStreamTransportBridgesRawBytesAndEOF() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let transport = SSHTCPIPChannelByteStreamTransport(handle: channel)

    try await transport.send(Array("PING".utf8), endOfStream: false)
    try await transport.send([], endOfStream: true)

    let firstChunk = try await transport.receive(atLeast: 1, atMost: 4096)
    let secondChunk = try await transport.receive(atLeast: 1, atMost: 4096)

    #expect(firstChunk.bytes == inboundData)
    #expect(!firstChunk.endOfStream)
    #expect(secondChunk.bytes.isEmpty)
    #expect(secondChunk.endOfStream)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func portForwardingBridgeCopiesBytesBetweenLocalTransportAndDirectTCPIPChannel() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let localTransport = MockLocalPortForwardTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: Array("PING".utf8), endOfStream: false),
            SSHByteStreamChunk(bytes: [], endOfStream: true),
        ]
    )

    try await SSHPortForwardingBridge().bridge(
        localTransport: localTransport,
        remoteChannel: channel
    )

    let sentEvents = await localTransport.recordedSentEvents()
    #expect(
        sentEvents
            == [
                .init(bytes: inboundData, endOfStream: false),
                .init(bytes: [], endOfStream: true),
            ]
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    let encryptedPayloads = Array(sentPayloads.dropFirst(2))
    var encryptedBytes: [UInt8] = []
    for payload in encryptedPayloads {
        encryptedBytes += payload
    }

    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: encryptedBytes)

    var connectionMessages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        if let message = try? SSHConnectionMessageParser().parse(packet.payload) {
            connectionMessages.append(message)
        }
    }

    #expect(
        connectionMessages.contains(
            .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 73,
                    data: Array("PING".utf8)
                )
            )
        )
    )
    #expect(
        connectionMessages.contains(
            .channelClose(
                SSHChannelCloseMessage(recipientChannel: 73)
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func portForwardingBridgeIgnoresOperationCanceledWhenClosingLocalTransport() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let localTransport = MockLocalPortForwardTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: Array("PING".utf8), endOfStream: false),
            SSHByteStreamChunk(bytes: [], endOfStream: true),
        ],
        terminalSendError: operationCanceledNSError
    )

    try await SSHPortForwardingBridge().bridge(
        localTransport: localTransport,
        remoteChannel: channel
    )

    let sentEvents = await localTransport.recordedSentEvents()
    #expect(
        sentEvents
            == [
                .init(bytes: inboundData, endOfStream: false),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func portForwardingBridgeClosesChannelAfterRemoteEOFWithoutWaitingForRemoteClose() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("EOF without close".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let localTransport = MockLocalPortForwardTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: Array("PING".utf8), endOfStream: false),
            SSHByteStreamChunk(bytes: [], endOfStream: true),
        ]
    )

    try await SSHPortForwardingBridge().bridge(
        localTransport: localTransport,
        remoteChannel: channel
    )

    let sentEvents = await localTransport.recordedSentEvents()
    #expect(
        sentEvents
            == [
                .init(bytes: inboundData, endOfStream: false),
                .init(bytes: [], endOfStream: true),
            ]
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    let encryptedPayloads = Array(sentPayloads.dropFirst(2))
    var encryptedBytes: [UInt8] = []
    for payload in encryptedPayloads {
        encryptedBytes += payload
    }

    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: encryptedBytes)

    var connectionMessages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        if let message = try? SSHConnectionMessageParser().parse(packet.payload) {
            connectionMessages.append(message)
        }
    }

    #expect(
        connectionMessages.contains(
            .channelClose(
                SSHChannelCloseMessage(recipientChannel: 73)
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func portForwardingBridgePreservesRemoteResponseAfterLocalEOF() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let localTransport = MockLocalPortForwardTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: Array("GET / HTTP/1.1\r\nHost: db.internal\r\n\r\n".utf8), endOfStream: false),
            SSHByteStreamChunk(bytes: [], endOfStream: true),
        ]
    )

    try await SSHPortForwardingBridge().bridge(
        localTransport: localTransport,
        remoteChannel: channel
    )

    let sentEvents = await localTransport.recordedSentEvents()
    #expect(
        sentEvents
            == [
                .init(bytes: inboundData, endOfStream: false),
                .init(bytes: [], endOfStream: true),
            ]
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    let encryptedPayloads = Array(sentPayloads.dropFirst(2))
    var encryptedBytes: [UInt8] = []
    for payload in encryptedPayloads {
        encryptedBytes += payload
    }

    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: encryptedBytes)

    var connectionMessages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        if let message = try? SSHConnectionMessageParser().parse(packet.payload) {
            connectionMessages.append(message)
        }
    }

    #expect(
        connectionMessages.contains(
            .channelEOF(
                SSHChannelEOFMessage(recipientChannel: 73)
            )
        )
    )
    #expect(
        connectionMessages.contains(
            .channelClose(
                SSHChannelCloseMessage(recipientChannel: 73)
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func portForwardingBridgeCancellationKeepsSharedTransportUsable() async throws {
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
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61001)
    )
    let localTransport = MockLocalPortForwardTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: [], endOfStream: true),
        ]
    )

    var serverSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serverSerializer.serialize(payload: payload)
    }

    let bridgeTask = Task {
        try await SSHPortForwardingBridge().bridge(
            localTransport: localTransport,
            remoteChannel: channel
        )
    }
    #expect(
        await waitUntil {
            await fixture.transport.activeReceiveCountObserved() > 0
        }
    )

    bridgeTask.cancel()
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: channel.channel.localChannelID))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: closePayload),
            endOfStream: false
        ),
    ])

    do {
        try await withOptionalTimeout(
            nanoseconds: 1_000_000_000,
            timeoutError: SSHTimeoutError.connectionSetup(durationNanoseconds: 1_000_000_000)
        ) {
            try await bridgeTask.value
        }
    } catch is CancellationError {
    }

    var allocatedPortWriter = SSHWireWriter()
    allocatedPortWriter.write(uint32: 47_000)
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: allocatedPortWriter.bytes))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: requestSuccessPayload),
            endOfStream: false
        ),
    ])

    let forward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 0
    )
    #expect(forward.portToBind == 47_000)
}
