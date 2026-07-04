// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientOpensDirectTCPIPChannelAndTransfersBytes() async throws {
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
                senderChannel: 55,
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
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
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
    let receiveFlagsBeforeChannelOpen = await fixture.transport.receiveRespectCancellationFlagsObserved()
    let channelOpenTask = Task {
        try await fixture.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(host: "db.internal", port: 5432),
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
        )
    }
    defer {
        channelOpenTask.cancel()
    }
    #expect(
        await waitUntil {
            await fixture.transport.activeReceiveCountObserved() > 0
        }
    )
    let receiveFlagsDuringChannelOpen = await fixture.transport.receiveRespectCancellationFlagsObserved()
    #expect(receiveFlagsDuringChannelOpen.dropFirst(receiveFlagsBeforeChannelOpen.count).contains(false))
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: openConfirmationPayload),
            endOfStream: false
        ),
    ])
    let channel = try await channelOpenTask.value
    try await channel.write(Array("ping".utf8))
    try await channel.sendEOF()
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: dataPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: eofPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: closePayload),
            endOfStream: false
        ),
    ])

    let firstChunk = try await channel.readChunk()
    let secondChunk = try await channel.readChunk()

    #expect(channel.channel.localChannelID == 0)
    #expect(channel.channel.remoteChannelID == 55)
    #expect(firstChunk == inboundData)
    #expect(secondChunk == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6] +
            sentPayloads[7]
    )
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let outboundDataPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    #expect(sentPayloads.count == 8)
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(authRequestPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
                )
            )
    )

    let openMessage = try SSHConnectionMessageParser().parse(openPacket.payload)
    let channelOpen = try #require({
        if case let .channelOpen(value) = openMessage {
            return value
        }
        return nil
    }())
    #expect(
        try forwardingCoder.parseDirectTCPIPChannelOpen(from: channelOpen)
            == SSHDirectTCPIPChannelOpenRequest(
                hostToConnect: "db.internal",
                portToConnect: 5432,
                originatorAddress: "127.0.0.1",
                originatorPort: 61321
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(outboundDataPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 55,
                    data: Array("ping".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(
                SSHChannelEOFMessage(recipientChannel: 55)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 55)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientOpensDirectStreamLocalChannelAndTransfersBytes() async throws {
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
                senderChannel: 56,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("PONG".utf8)
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
    let channel = try await fixture.client.openDirectStreamLocalChannel(
        socketPath: "/run/postgresql/.s.PGSQL.5432",
        originatorAddress: "127.0.0.1",
        originatorPort: 61321
    )
    try await channel.write(Array("PING".utf8))
    try await channel.sendEOF()

    let firstChunk = try await channel.readChunk()
    let secondChunk = try await channel.readChunk()

    #expect(channel.channel.localChannelID == 0)
    #expect(channel.channel.remoteChannelID == 56)
    #expect(firstChunk == inboundData)
    #expect(secondChunk == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6] +
            sentPayloads[7]
    )
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let outboundDataPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    #expect(sentPayloads.count == 8)
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(authRequestPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
                )
            )
    )

    let openMessage = try SSHConnectionMessageParser().parse(openPacket.payload)
    let channelOpen = try #require({
        if case let .channelOpen(value) = openMessage {
            return value
        }
        return nil
    }())
    #expect(
        try forwardingCoder.parseDirectStreamLocalChannelOpen(from: channelOpen)
            == SSHDirectStreamLocalChannelOpenRequest(
                socketPath: "/run/postgresql/.s.PGSQL.5432",
                originatorAddress: "127.0.0.1",
                originatorPort: 61321
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(outboundDataPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 56,
                    data: Array("PING".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(
                SSHChannelEOFMessage(recipientChannel: 56)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 56)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpipChannelBackedTransportSendCanIgnoreCallerCancellation() async throws {
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
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
        ],
        sendDelayNanoseconds: 100_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )
    let transport = SSHTCPIPChannelByteStreamTransport(handle: channel)

    let sendTask = Task {
        try await transport.send(
            Array("PING".utf8),
            endOfStream: false,
            respectCancellation: false
        )
    }
    try await Task.sleep(nanoseconds: 10_000_000)
    sendTask.cancel()
    try await sendTask.value

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })

    var channelDataMessages: [SSHChannelDataMessage] = []
    while let packet = try parser.nextPacket() {
        if case let .channelData(message) =
            try? SSHConnectionMessageParser().parse(packet.payload) {
            channelDataMessages.append(message)
        }
    }

    #expect(
        channelDataMessages.contains(
            SSHChannelDataMessage(
                recipientChannel: 55,
                data: Array("PING".utf8)
            )
        )
    )
}

@Test
func tcpipChannelByteStreamTransportCloseReturnsBeforeChannelCloseSendCompletes() async throws {
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
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
        ],
        sendDelayNanoseconds: 200_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )
    let transport = SSHTCPIPChannelByteStreamTransport(handle: channel)

    try await withOptionalTimeout(
        nanoseconds: 50_000_000,
        timeoutError: SSHTimeoutError.connectionSetup(durationNanoseconds: 50_000_000)
    ) {
        await transport.close()
    }

    #expect(
        await waitUntil(maxAttempts: 20, sleepNanoseconds: 25_000_000) {
            await sentForwardingConnectionMessages(
                from: fixture.transport,
                activation: fixture.activation,
                initialSequenceNumber: 1
            ).contains { message in
                if case let .channelClose(close) = message {
                    return close.recipientChannel == 55
                }
                return false
            }
        }
    )
}

private func sentForwardingConnectionMessages(
    from transport: ProtocolClientMockSSHByteStreamTransport,
    activation: SSHCurve25519TransportActivation,
    initialSequenceNumber: UInt32
) async -> [SSHConnectionMessage] {
    let sentPayloads = await transport.sentPayloads()
    guard sentPayloads.count > 2 else {
        return []
    }

    do {
        var parser = try SSHInboundEncryptedPacketParser(
            negotiatedAlgorithms: activation.negotiation.algorithms,
            keyMaterial: activation.transportKeyMaterial,
            direction: .clientToServer,
            initialSequenceNumber: initialSequenceNumber
        )
        parser.append(bytes: sentPayloads.dropFirst(2).flatMap { $0 })

        var messages: [SSHConnectionMessage] = []
        while let packet = try parser.nextPacket() {
            if let message = try? SSHConnectionMessageParser().parse(packet.payload) {
                messages.append(message)
            }
        }
        return messages
    } catch {
        return []
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadsDirectTCPIPChannelEventsIncrementally() async throws {
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
                senderChannel: 55,
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
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )

    #expect(try await channel.readEvent() == .data(inboundData))
    #expect(try await channel.readEvent() == .endOfFile)
    #expect(try await channel.readEvent() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientQueuesForwardedTCPIPChannelWhileWaitingForDirectTCPIPConfirmation() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: 8022)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: 62001)
                    return writer.bytes
                }()
            )
        )
    )
    let directConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 77,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            forwardedOpenPayload,
            directConfirmationPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )
    let directChannel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "127.0.0.1", port: 8022),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )
    let acceptedChannel = try await fixture.client.acceptForwardedTCPIPChannel(
        for: activeForward
    )

    #expect(directChannel.channel.localChannelID == 0)
    #expect(directChannel.channel.remoteChannelID == 77)
    #expect(acceptedChannel.handle.channel.localChannelID == 1)
    #expect(acceptedChannel.handle.channel.remoteChannelID == 55)
    #expect(
        acceptedChannel.openRequest
            == SSHForwardedTCPIPChannelOpenRequest(
                listeningAddress: "127.0.0.1",
                listeningPort: 8022,
                originatorAddress: "198.51.100.7",
                originatorPort: 62001
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let directOpenPacket = try #require(try parser.nextPacket())
    let forwardedConfirmationPacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let requestGlobal = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    #expect(requestGlobal.requestName == "tcpip-forward")

    let directOpenMessage = try SSHConnectionMessageParser().parse(directOpenPacket.payload)
    let directOpen = try #require({
        if case let .channelOpen(value) = directOpenMessage {
            return value
        }
        return nil
    }())
    #expect(
        try forwardingCoder.parseDirectTCPIPChannelOpen(from: directOpen)
            == SSHDirectTCPIPChannelOpenRequest(
                hostToConnect: "127.0.0.1",
                portToConnect: 8022,
                originatorAddress: "127.0.0.1",
                originatorPort: 61321
            )
    )

    #expect(
        try SSHConnectionMessageParser().parse(forwardedConfirmationPacket.payload)
            == .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: 55,
                    senderChannel: 1,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSerializesConcurrentReceivesAcrossDirectOpenAndForwardAccept() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: 8022)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: 62001)
                    return writer.bytes
                }()
            )
        )
    )
    let directConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 77,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            forwardedOpenPayload,
            directConfirmationPayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let directChannelTask = Task {
        try await fixture.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(host: "127.0.0.1", port: 8022),
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
        )
    }
    defer {
        directChannelTask.cancel()
    }

    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let acceptedChannelTask = Task {
        try await fixture.client.acceptForwardedTCPIPChannel(
            for: activeForward
        )
    }
    defer {
        acceptedChannelTask.cancel()
    }

    let directChannel = try await directChannelTask.value
    let acceptedChannel = try await acceptedChannelTask.value

    #expect(directChannel.channel.localChannelID == 0)
    #expect(directChannel.channel.remoteChannelID == 77)
    #expect(acceptedChannel.handle.channel.localChannelID == 1)
    #expect(acceptedChannel.handle.channel.remoteChannelID == 55)
    #expect(await fixture.transport.maximumConcurrentReceiveCountObserved() == 1)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientMarksForwardedTCPIPChannelPendingBeforeConfirmationSendCompletes() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ],
        sendDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let open = SSHChannelOpenMessage(
        channelType: "forwarded-tcpip",
        senderChannel: 55,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        channelTypeData: []
    )
    let request = SSHForwardedTCPIPChannelOpenRequest(
        listeningAddress: "127.0.0.1",
        listeningPort: 8022,
        originatorAddress: "198.51.100.7",
        originatorPort: 62001
    )
    let acceptTask = Task {
        try await fixture.client.acceptIncomingForwardedTCPIPChannelOpen(
            open,
            request: request,
            localInitialWindowSize: 1_048_576,
            localMaximumPacketSize: 32_768
        )
    }
    defer {
        acceptTask.cancel()
    }

    #expect(
        await waitUntil {
            await fixture.transport.activeSendCountObserved() > 0
        }
    )
    #expect(await fixture.client.pendingManagedSessionLocalChannelIDs.contains(0))

    let acceptedChannel = try await acceptTask.value
    #expect(await fixture.client.pendingManagedSessionLocalChannelIDs.isEmpty)
    #expect(await fixture.client.managedSessionStates[0] != nil)

    try await acceptedChannel.handle.close()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRequestsRemoteTCPIPForwardAndReturnsAllocatedPort() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    var successWriter = SSHWireWriter()
    successWriter.write(uint32: 47_000)
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(
            SSHGlobalRequestSuccessMessage(responseData: successWriter.bytes)
        )
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
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
    let receiveFlagsBeforeRequest = await fixture.transport.receiveRespectCancellationFlagsObserved()
    let requestTask = Task {
        try await fixture.client.requestTCPIPForward(
            addressToBind: "127.0.0.1",
            portToBind: 0
        )
    }
    defer {
        requestTask.cancel()
    }
    #expect(
        await waitUntil {
            await fixture.transport.activeReceiveCountObserved() > 0
        }
    )
    let receiveFlagsDuringRequest = await fixture.transport.receiveRespectCancellationFlagsObserved()
    #expect(receiveFlagsDuringRequest.dropFirst(receiveFlagsBeforeRequest.count).contains(false))
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: requestSuccessPayload),
            endOfStream: false
        ),
    ])
    let activeForward = try await requestTask.value

    #expect(
        activeForward == SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 47_000
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let globalRequest = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    #expect(globalRequest.wantReply)
    #expect(
        try forwardingCoder.parseForwardRequest(from: globalRequest)
            == SSHTCPIPForwardingRequest(
                addressToBind: "127.0.0.1",
                portToBind: 0
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsRemoteTCPIPForward() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            cancelSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )
    try await fixture.client.cancelTCPIPForward(activeForward)

    #expect(
        activeForward == SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 8022
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let cancelPacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let requestGlobal = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    #expect(requestGlobal.requestName == "tcpip-forward")
    #expect(
        try forwardingCoder.parseForwardRequest(from: requestGlobal)
            == activeForward
    )

    let cancelMessage = try SSHConnectionMessageParser().parse(cancelPacket.payload)
    let cancelGlobal = try #require({
        if case let .globalRequest(value) = cancelMessage {
            return value
        }
        return nil
    }())
    #expect(cancelGlobal.requestName == "cancel-tcpip-forward")
    #expect(
        try forwardingCoder.parseCancelForwardRequest(from: cancelGlobal)
            == activeForward
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelledRemoteTCPIPAcceptDoesNotCancelSharedReceive()
    async throws
{
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        requestSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )

    let acceptTask = Task {
        try await fixture.client.acceptForwardedTCPIPChannel(for: activeForward)
    }
    #expect(
        await waitUntil {
            await fixture.transport.activeReceiveCountObserved() > 0
        }
    )

    acceptTask.cancel()
    try await Task.sleep(nanoseconds: 20_000_000)
    #expect(await fixture.transport.activeReceiveCountObserved() > 0)

    var serverSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serverSerializer.serialize(payload: payload)
    }
    let interleavedGlobalReply = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: interleavedGlobalReply),
            endOfStream: false
        ),
    ])

    do {
        _ = try await withOptionalTimeout(
            nanoseconds: 1_000_000_000,
            timeoutError: SSHTimeoutError.connectionSetup(durationNanoseconds: 1_000_000_000)
        ) {
            try await acceptTask.value
        }
        Issue.record("Expected cancelled remote TCP/IP accept to throw CancellationError.")
    } catch is CancellationError {
    }

    let reply = try await fixture.client.receiveGlobalRequestReplyMessage(
        requestType: "cancel-tcpip-forward"
    )
    #expect(reply == .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: [])))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRequestsRemoteStreamLocalForwardAndCancelsIt() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            cancelSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestStreamLocalForward(
        socketPath: "/tmp/traversio.sock"
    )
    try await fixture.client.cancelStreamLocalForward(activeForward)

    #expect(
        activeForward == SSHStreamLocalForwardingRequest(
            socketPath: "/tmp/traversio.sock"
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let cancelPacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let requestGlobal = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    #expect(requestGlobal.requestName == "streamlocal-forward@openssh.com")
    #expect(
        try forwardingCoder.parseStreamLocalForwardRequest(from: requestGlobal)
            == activeForward
    )

    let cancelMessage = try SSHConnectionMessageParser().parse(cancelPacket.payload)
    let cancelGlobal = try #require({
        if case let .globalRequest(value) = cancelMessage {
            return value
        }
        return nil
    }())
    #expect(cancelGlobal.requestName == "cancel-streamlocal-forward@openssh.com")
    #expect(
        try forwardingCoder.parseCancelStreamLocalForwardRequest(from: cancelGlobal)
            == activeForward
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAcceptsForwardedTCPIPChannelAndTransfersBytes() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: 8022)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: 62001)
                    return writer.bytes
                }()
            )
        )
    )
    let inboundData = Array("PING".utf8)
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
            requestSuccessPayload,
            forwardedOpenPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )
    let acceptedChannel = try await fixture.client.acceptForwardedTCPIPChannel(
        for: activeForward
    )

    try await acceptedChannel.handle.write(Array("PONG".utf8))
    try await acceptedChannel.handle.sendEOF()

    let firstChunk = try await acceptedChannel.handle.readChunk()
    let secondChunk = try await acceptedChannel.handle.readChunk()

    #expect(
        acceptedChannel.openRequest
            == SSHForwardedTCPIPChannelOpenRequest(
                listeningAddress: "127.0.0.1",
                listeningPort: 8022,
                originatorAddress: "198.51.100.7",
                originatorPort: 62001
            )
    )
    #expect(acceptedChannel.handle.channel.localChannelID == 0)
    #expect(acceptedChannel.handle.channel.remoteChannelID == 55)
    #expect(firstChunk == inboundData)
    #expect(secondChunk == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] +
            sentPayloads[6] + sentPayloads[7]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let confirmationPacket = try #require(try parser.nextPacket())
    let outboundDataPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let requestGlobal = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    #expect(
        try forwardingCoder.parseForwardRequest(from: requestGlobal)
            == activeForward
    )

    #expect(
        try SSHConnectionMessageParser().parse(confirmationPacket.payload)
            == .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: 55,
                    senderChannel: 0,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(outboundDataPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 55,
                    data: Array("PONG".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(SSHChannelEOFMessage(recipientChannel: 55))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAcceptsForwardedStreamLocalChannelAndTransfersBytes() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-streamlocal@openssh.com",
                senderChannel: 57,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "/tmp/traversio.sock")
                    writer.write(utf8: "")
                    return writer.bytes
                }()
            )
        )
    )
    let inboundData = Array("PING".utf8)
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
            requestSuccessPayload,
            forwardedOpenPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestStreamLocalForward(
        socketPath: "/tmp/traversio.sock"
    )
    let acceptedChannel = try await fixture.client.acceptForwardedStreamLocalChannel(
        for: activeForward
    )

    try await acceptedChannel.handle.write(Array("PONG".utf8))
    try await acceptedChannel.handle.sendEOF()

    let firstChunk = try await acceptedChannel.handle.readChunk()
    let secondChunk = try await acceptedChannel.handle.readChunk()

    #expect(
        acceptedChannel.openRequest
            == SSHForwardedStreamLocalChannelOpenRequest(
                socketPath: "/tmp/traversio.sock"
            )
    )
    #expect(acceptedChannel.handle.channel.localChannelID == 0)
    #expect(acceptedChannel.handle.channel.remoteChannelID == 57)
    #expect(firstChunk == inboundData)
    #expect(secondChunk == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] +
            sentPayloads[6] + sentPayloads[7]
    )
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let requestPacket = try #require(try parser.nextPacket())
    let confirmationPacket = try #require(try parser.nextPacket())
    let outboundDataPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()

    let requestMessage = try SSHConnectionMessageParser().parse(requestPacket.payload)
    let requestGlobal = try #require({
        if case let .globalRequest(value) = requestMessage {
            return value
        }
        return nil
    }())
    #expect(
        try forwardingCoder.parseStreamLocalForwardRequest(from: requestGlobal)
            == activeForward
    )

    #expect(
        try SSHConnectionMessageParser().parse(confirmationPacket.payload)
            == .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: 57,
                    senderChannel: 0,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(outboundDataPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 57,
                    data: Array("PONG".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(SSHChannelEOFMessage(recipientChannel: 57))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientQueuesForwardedStreamLocalChannelWhileWaitingForTCPIPAccept() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let tcpForwardSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let streamLocalForwardSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let streamLocalOpenPayload = try SSHConnectionMessageSerializer().serialize(
        SSHTCPIPForwardingRequestCoder().makeForwardedStreamLocalChannelOpen(
            senderChannel: 61,
            initialWindowSize: 1_048_576,
            maximumPacketSize: 32_768,
            request: SSHForwardedStreamLocalChannelOpenRequest(
                socketPath: "/tmp/traversio.sock"
            )
        )
    )
    let tcpOpenPayload = try SSHConnectionMessageSerializer().serialize(
        SSHTCPIPForwardingRequestCoder().makeForwardedTCPIPChannelOpen(
            senderChannel: 62,
            initialWindowSize: 1_048_576,
            maximumPacketSize: 32_768,
            request: SSHForwardedTCPIPChannelOpenRequest(
                listeningAddress: "127.0.0.1",
                listeningPort: 8022,
                originatorAddress: "198.51.100.7",
                originatorPort: 62001
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            tcpForwardSuccessPayload,
            streamLocalForwardSuccessPayload,
            streamLocalOpenPayload,
            tcpOpenPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let tcpForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )
    let streamLocalForward = try await fixture.client.requestStreamLocalForward(
        socketPath: "/tmp/traversio.sock"
    )

    let acceptedTCPIPChannel = try await fixture.client.acceptForwardedTCPIPChannel(
        for: tcpForward
    )
    let acceptedStreamLocalChannel = try await fixture.client.acceptForwardedStreamLocalChannel(
        for: streamLocalForward
    )

    #expect(acceptedTCPIPChannel.handle.channel.localChannelID == 1)
    #expect(acceptedTCPIPChannel.handle.channel.remoteChannelID == 62)
    #expect(
        acceptedTCPIPChannel.openRequest == SSHForwardedTCPIPChannelOpenRequest(
            listeningAddress: "127.0.0.1",
            listeningPort: 8022,
            originatorAddress: "198.51.100.7",
            originatorPort: 62001
        )
    )
    #expect(acceptedStreamLocalChannel.handle.channel.localChannelID == 0)
    #expect(acceptedStreamLocalChannel.handle.channel.remoteChannelID == 61)
    #expect(
        acceptedStreamLocalChannel.openRequest == SSHForwardedStreamLocalChannelOpenRequest(
            socketPath: "/tmp/traversio.sock"
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSurfacesRemoteTCPIPForwardFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestFailurePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    do {
        _ = try await fixture.client.requestTCPIPForward(
            addressToBind: "127.0.0.1",
            portToBind: 8022
        )
        Issue.record("Expected tcpip-forward request failure")
    } catch {
        #expect(
            error as? SSHConnectionError
                == .globalRequestFailed(requestType: "tcpip-forward")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSurfacesDirectTCPIPOpenFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let failure = SSHChannelOpenFailureMessage(
        recipientChannel: 0,
        reasonCode: .connectFailed,
        description: "connection refused",
        languageTag: ""
    )
    let openFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenFailure(failure)
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openFailurePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    do {
        _ = try await fixture.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(host: "db.internal", port: 5432),
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
        )
        Issue.record("Expected direct-tcpip open failure")
    } catch {
        #expect(error as? SSHConnectionError == .channelOpenFailure(failure))
    }
}

// Cancelling a remote forward that still has an accepted-but-unhanded forwarded channel
// queued must tear that channel down (CHANNEL_CLOSE and managed-session state removed) instead of
// leaving it confirmed-open and leaking managed-session state until connection close.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelTCPIPForwardDrainsQueuedForwardedChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            cancelSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 8022
    )

    // Simulate an inbound forwarded-tcpip open that is fully accepted while no accept() caller is
    // waiting: it is confirmed-open, registered as a managed session, and queued.
    let forwardedOpen = SSHChannelOpenMessage(
        channelType: "forwarded-tcpip",
        senderChannel: 90,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        channelTypeData: {
            var writer = SSHWireWriter()
            writer.write(utf8: "127.0.0.1")
            writer.write(uint32: 8022)
            writer.write(utf8: "198.51.100.7")
            writer.write(uint32: 62001)
            return writer.bytes
        }()
    )
    _ = try await fixture.client.queueForwardedTCPIPChannelOpenIfActive(
        forwardedOpen,
        localInitialWindowSize: 1_048_576,
        localMaximumPacketSize: 32_768
    )

    // Precondition: the queued channel is confirmed-open and its managed-session state exists.
    #expect(await fixture.client.managedSessionStates[0] != nil)
    #expect(await fixture.client.pendingForwardedTCPIPChannels[activeForward]?.count == 1)

    try await fixture.client.cancelTCPIPForward(activeForward)

    // The queued channel must be closed and its state removed, not leaked.
    #expect(await fixture.client.managedSessionStates[0] == nil)
    #expect(await fixture.client.pendingForwardedTCPIPChannels[activeForward] == nil)

    let sentMessages = await sentForwardingConnectionMessages(
        from: fixture.transport,
        activation: fixture.activation,
        initialSequenceNumber: 1
    )
    #expect(
        sentMessages.contains { message in
            if case let .channelClose(close) = message {
                return close.recipientChannel == 90
            }
            return false
        }
    )
}

// A global request whose waiter times out abandons its turn while its reply may still be in
// flight. When that stale reply arrives it must NOT be handed to the next, unrelated global
// request (which would, e.g., adopt attempt 1's bound port as attempt 2's answer).
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDoesNotDeliverAbandonedGlobalRequestReplyToNextRequest() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let setupPayloads = [serviceAcceptPayload, authSuccessPayload]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks,
        responseTimeoutNanoseconds: 100_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
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

    // Attempt 1 times out: its request is on the wire but no reply is delivered yet.
    do {
        _ = try await fixture.client.requestTCPIPForward(
            addressToBind: "127.0.0.1",
            portToBind: 0
        )
        Issue.record("Expected attempt 1 to time out.")
    } catch {
        #expect(
            error as? SSHTimeoutError
                == .globalRequestReply(
                    requestType: "tcpip-forward",
                    durationNanoseconds: 100_000_000
                )
        )
    }

    // Attempt 1's LATE reply arrives (bound port 47000), followed by attempt 2's real reply
    // (bound port 48000). Consumption order matches send order, so the stale reply is first.
    var staleReplyWriter = SSHWireWriter()
    staleReplyWriter.write(uint32: 47_000)
    let staleReplyPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: staleReplyWriter.bytes))
    )
    var liveReplyWriter = SSHWireWriter()
    liveReplyWriter.write(uint32: 48_000)
    let liveReplyPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: liveReplyWriter.bytes))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: staleReplyPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: liveReplyPayload),
            endOfStream: false
        ),
    ])

    // Attempt 2 must receive its OWN reply (48000), not attempt 1's abandoned reply (47000).
    let secondForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 0
    )
    #expect(
        secondForward == SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 48_000
        )
    )
}

// After churning far more than the former 256-entry completed-channel LRU, a late WINDOW_ADJUST
// for one of the earliest completed channels must be tolerated and must NOT fail an unrelated,
// healthy in-flight channel open with unknownChannel.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientToleratesLateMessageForEvictedCompletedChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let churnCount: UInt32 = 260
    var serverPayloads: [[UInt8]] = [serviceAcceptPayload, authSuccessPayload]
    for index in 0..<churnCount {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelOpenConfirmation(
                    SSHChannelOpenConfirmationMessage(
                        recipientChannel: index,
                        senderChannel: 1_000 + index,
                        initialWindowSize: 1_048_576,
                        maximumPacketSize: 32_768,
                        channelTypeData: []
                    )
                )
            )
        )
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelClose(SSHChannelCloseMessage(recipientChannel: index))
            )
        )
    }
    // A late window-adjust for the long-evicted channel 0, interleaved before the healthy open's
    // confirmation.
    serverPayloads.append(
        try SSHConnectionMessageSerializer().serialize(
            .channelWindowAdjust(
                SSHChannelWindowAdjustMessage(recipientChannel: 0, bytesToAdd: 1_024)
            )
        )
    )
    serverPayloads.append(
        try SSHConnectionMessageSerializer().serialize(
            .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: churnCount,
                    senderChannel: 5_000,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: serverPayloads
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    for index in 0..<churnCount {
        let channel = try await fixture.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(host: "db.internal", port: 5432),
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
        )
        #expect(channel.channel.localChannelID == index)
        #expect(try await channel.readChunk() == nil)
    }

    // The healthy open must succeed even though a late message for evicted channel 0 arrives
    // interleaved with its confirmation.
    let healthyChannel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )
    #expect(healthyChannel.channel.localChannelID == churnCount)
    #expect(await fixture.client.managedSessionStates[churnCount] != nil)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientClosesLateConfirmationForAbandonedChannelOpen() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let setupPayloads = [serviceAcceptPayload, authSuccessPayload]
    let responseTimeoutNanoseconds: UInt64 = 50_000_000
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks,
        responseTimeoutNanoseconds: responseTimeoutNanoseconds
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
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

    do {
        _ = try await fixture.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(host: "db.internal", port: 5432),
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
        )
        Issue.record("Expected the first channel open to time out.")
    } catch {
        #expect(
            error as? SSHTimeoutError
                == .channelOpenResponse(durationNanoseconds: responseTimeoutNanoseconds)
        )
    }
    #expect(await fixture.client.abandonedManagedSessionLocalChannelIDs.contains(0))

    let staleConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 9_000,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let staleClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let liveConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 9_001,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: staleConfirmationPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: staleClosePayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: liveConfirmationPayload),
            endOfStream: false
        ),
    ])

    let liveChannel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )

    #expect(liveChannel.channel.localChannelID == 1)
    #expect(liveChannel.channel.remoteChannelID == 9_001)
    #expect(await !fixture.client.abandonedManagedSessionLocalChannelIDs.contains(0))

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads.dropFirst(2).flatMap { $0 })

    var sentConnectionMessages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        if let message = try? SSHConnectionMessageParser().parse(packet.payload) {
            sentConnectionMessages.append(message)
        }
    }

    #expect(
        sentConnectionMessages.contains(
            .channelClose(SSHChannelCloseMessage(recipientChannel: 9_000))
        )
    )
}

// A late reply belonging to an abandoned global request (reply timeout or cancellation) is
// an expected arrival at a remote-forward accept loop: the abandoned-reply counter drops it
// before any future waiter can match it. The accept loop must keep accepting, not die.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAcceptLoopSurvivesAbandonedGlobalRequestLateReply() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let setupPayloads = [serviceAcceptPayload, authSuccessPayload]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks,
        responseTimeoutNanoseconds: 100_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
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

    // Establish the forward (bound port 47000) and park its accept loop on the receive turn.
    var forwardReplyWriter = SSHWireWriter()
    forwardReplyWriter.write(uint32: 47_000)
    let forwardReplyPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: forwardReplyWriter.bytes))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: forwardReplyPayload),
            endOfStream: false
        ),
    ])
    let activeForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 0
    )
    let acceptTask = Task {
        try await fixture.client.acceptForwardedTCPIPChannel(for: activeForward)
    }
    var acceptLoopParked = false
    for _ in 0..<400 {
        if await fixture.client.activeConnectionMessageWaiterCount == 1 {
            acceptLoopParked = true
            break
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(acceptLoopParked)

    // A second global request times out and abandons its turn while its reply is in flight.
    do {
        _ = try await fixture.client.requestTCPIPForward(
            addressToBind: "127.0.0.1",
            portToBind: 0
        )
        Issue.record("Expected the second forward request to time out.")
    } catch {
        #expect(
            error as? SSHTimeoutError
                == .globalRequestReply(
                    requestType: "tcpip-forward",
                    durationNanoseconds: 100_000_000
                )
        )
    }
    #expect(await fixture.client.abandonedGlobalRequestReplyCount == 1)

    // The abandoned request's LATE reply now reaches the parked accept loop. It must be
    // queued for the abandoned-reply drop, not treated as a fatal unsolicited reply.
    var staleReplyWriter = SSHWireWriter()
    staleReplyWriter.write(uint32: 48_000)
    let staleReplyPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: staleReplyWriter.bytes))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: 47_000)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: 62001)
                    return writer.bytes
                }()
            )
        )
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: staleReplyPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: forwardedOpenPayload),
            endOfStream: false
        ),
    ])

    // The accept loop survives the stale reply and accepts the forwarded connection.
    let acceptedChannel = try await acceptTask.value
    #expect(acceptedChannel.handle.channel.remoteChannelID == 55)
    #expect(
        acceptedChannel.openRequest
            == SSHForwardedTCPIPChannelOpenRequest(
                listeningAddress: "127.0.0.1",
                listeningPort: 47_000,
                originatorAddress: "198.51.100.7",
                originatorPort: 62001
            )
    )

    // The queued stale reply is dropped by the abandoned-reply counter, so a third request
    // still matches its OWN reply (49000), not the abandoned one (48000).
    var liveReplyWriter = SSHWireWriter()
    liveReplyWriter.write(uint32: 49_000)
    let liveReplyPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: liveReplyWriter.bytes))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: liveReplyPayload),
            endOfStream: false
        ),
    ])
    let thirdForward = try await fixture.client.requestTCPIPForward(
        addressToBind: "127.0.0.1",
        portToBind: 0
    )
    #expect(
        thirdForward == SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 49_000
        )
    )
}
