// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSendsKeepaliveAfterAuthenticationIdleInterval() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let keepaliveFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 0)
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
            keepaliveFailurePayload,
            keepaliveFailurePayload,
            openConfirmationPayload,
            channelSuccessPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ],
        keepalivePolicy: SSHTransportKeepalivePolicy(
            intervalNanoseconds: 50_000_000,
            responseTimeoutNanoseconds: 50_000_000
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let baselineSentCount = await fixture.transport.sentPayloads().count
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        )
    )
    #expect(
        await waitUntil(maxAttempts: 100, sleepNanoseconds: 5_000_000) {
            await fixture.client.currentLatency()?.source == .keepalive
        }
    )
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 2,
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        )
    )
    let latency = try #require(await fixture.client.currentLatency())
    #expect(latency.source == .keepalive)
    #expect(latency.measuredAtUptimeNanoseconds > 0)
    #expect(latency.roundTripTimeMilliseconds >= 0)

    let result = try await fixture.client.execute(command: "true")
    #expect(result.exitStatus == 0)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(2).joined()))

    var sawKeepalive = false
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.globalRequest.rawValue else {
            continue
        }

        let request = try #require({
            let message = try SSHConnectionMessageParser().parse(packet.payload)
            if case let .globalRequest(value) = message {
                return value
            }
            return nil
        }())
        if request.requestName == SSHTransportProtocolClient.keepaliveRequestName {
            sawKeepalive = true
            #expect(request.wantReply)
            #expect(request.requestData.isEmpty)
        }
    }

    #expect(sawKeepalive)
    await fixture.client.disconnect()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSurfacesBackgroundKeepaliveTimeoutOnNextOperation() async throws {
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
        emptyReceiveBehavior: .waitForAppendedChunks,
        keepalivePolicy: SSHTransportKeepalivePolicy(
            intervalNanoseconds: 50_000_000,
            responseTimeoutNanoseconds: 50_000_000
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let baselineSentCount = await fixture.transport.sentPayloads().count
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        )
    )
    try? await Task.sleep(nanoseconds: 100_000_000)

    do {
        _ = try await fixture.client.execute(command: "true")
        Issue.record("Expected the pending keepalive timeout to fail the next operation.")
    } catch {
        #expect(
            error as? SSHTimeoutError
                == .keepaliveReply(durationNanoseconds: 50_000_000)
        )
    }

    await fixture.client.cancelKeepaliveTask()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCompletesKeepaliveReplyRoutedByActiveSessionReader() async throws {
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
                senderChannel: 64,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let initialPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        ptySuccessPayload,
        shellSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: initialPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()
    var serverEncryptedPacketSerializer = try makeServerEncryptedPacketSerializer(
        activation: fixture.activation,
        afterSerializing: initialPayloads
    )

    let readTask = Task {
        try await session.readEvent()
    }
    #expect(
        await waitUntil {
            await fixture.client.activeConnectionMessageWaiterCount == 1
        }
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let keepaliveTask = Task {
        try await fixture.client.sendKeepalive(responseTimeoutNanoseconds: 500_000_000)
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        )
    )

    let keepaliveSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    await fixture.transport.appendReceiveChunks(
        try makeEncryptedServerChunks(
            [keepaliveSuccessPayload],
            serializer: &serverEncryptedPacketSerializer
        )
    )
    try await keepaliveTask.value
    let latency = try #require(await fixture.client.currentLatency())
    #expect(latency.source == .keepalive)
    #expect(latency.measuredAtUptimeNanoseconds > 0)
    #expect(latency.roundTripTimeMilliseconds >= 0)

    let outputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("reader-ok".utf8)
            )
        )
    )
    await fixture.transport.appendReceiveChunks(
        try makeEncryptedServerChunks(
            [outputPayload],
            serializer: &serverEncryptedPacketSerializer
        )
    )
    #expect(try await readTask.value == .standardOutput(Array("reader-ok".utf8)))
    await fixture.client.cancelKeepaliveTask()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRepliesFailureToUnknownChannelRequestWithWantReply() async throws {
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
                senderChannel: 64,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let initialPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        ptySuccessPayload,
        shellSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: initialPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()
    var serverEncryptedPacketSerializer = try makeServerEncryptedPacketSerializer(
        activation: fixture.activation,
        afterSerializing: initialPayloads
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let readTask = Task {
        try await session.readEvent()
    }
    #expect(
        await waitUntil {
            await fixture.client.activeConnectionMessageWaiterCount == 1
        }
    )

    let channelKeepalivePayload = try SSHConnectionMessageSerializer().serialize(
        .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: 0,
                requestType: "keepalive@openssh.com",
                wantReply: true,
                requestData: []
            )
        )
    )
    await fixture.transport.appendReceiveChunks(
        try makeEncryptedServerChunks(
            [channelKeepalivePayload],
            serializer: &serverEncryptedPacketSerializer
        )
    )
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        )
    )

    let outputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("after-channel-keepalive".utf8)
            )
        )
    )
    await fixture.transport.appendReceiveChunks(
        try makeEncryptedServerChunks(
            [outputPayload],
            serializer: &serverEncryptedPacketSerializer
        )
    )
    #expect(
        try await readTask.value
            == .standardOutput(Array("after-channel-keepalive".utf8))
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(2).joined()))

    var sawChannelFailure = false
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelFailure.rawValue else {
            continue
        }

        let failure = try #require({
            let message = try SSHConnectionMessageParser().parse(packet.payload)
            if case let .channelFailure(value) = message {
                return value
            }
            return nil
        }())
        if failure.recipientChannel == 64 {
            sawChannelFailure = true
        }
    }

    #expect(sawChannelFailure)
    await fixture.client.cancelKeepaliveTask()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeEncryptedServerChunks(
    _ payloads: [[UInt8]],
    serializer: inout SSHOutboundEncryptedPacketSerializer
) throws -> [SSHByteStreamChunk] {
    let bytes = try payloads.flatMap { payload in
        try serializer.serialize(payload: payload)
    }
    return [
        SSHByteStreamChunk(
            bytes: bytes,
            endOfStream: false
        ),
    ]
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeServerEncryptedPacketSerializer(
    activation: SSHCurve25519TransportActivation,
    afterSerializing payloads: [[UInt8]]
) throws -> SSHOutboundEncryptedPacketSerializer {
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: activation.negotiation.algorithms,
        keyMaterial: activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in payloads {
        _ = try serializer.serialize(payload: payload)
    }
    return serializer
}
