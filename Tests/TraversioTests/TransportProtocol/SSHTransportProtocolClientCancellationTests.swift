// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsIdentificationExchangeWhileWaitingForServerIdentification() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .delayedEndOfStream(
            delayNanoseconds: 200_000_000,
            ignoreCancellation: true
        )
    )
    let client = SSHTransportProtocolClient(transport: transport)

    await expectOperationCancellation {
        _ = try await client.exchangeIdentifications()
    }

    let sentPayloads = await transport.sentPayloads()
    #expect(sentPayloads.count == 1)
    #expect(sentPayloads[0].starts(with: Array(TraversioRelease.sshIdentificationRawValue.utf8)))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsManagedSessionWriteWhileWaitingForRemoteWindowAdjustment() async throws {
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
                senderChannel: 81,
                initialWindowSize: 0,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
        ],
        emptyReceiveBehavior: .delayedEndOfStream(
            delayNanoseconds: 200_000_000,
            ignoreCancellation: true
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openSFTPSubsystemSession()

    await expectOperationCancellation {
        try await session.write(Array("hello".utf8))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsSessionTranscriptCollectionBySendingChannelClose() async throws {
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
                senderChannel: 83,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
        ],
        emptyReceiveBehavior: .delayedEndOfStream(
            delayNanoseconds: 200_000_000,
            ignoreCancellation: true
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "sleep 300")
    let baselineSentCount = await fixture.transport.sentPayloads().count

    let task = Task {
        try await session.collectOutputUntilClose()
    }

    try? await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()

    do {
        _ = try await task.value
        Issue.record("Expected transcript collection cancellation")
    } catch {
        #expect(error is CancellationError)
    }

    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(2).joined()))

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    let closePacket = try #require(packets.last)
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 83)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientPreservesPacketReceivedDuringCancelledSessionRead() async throws {
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
                senderChannel: 84,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        channelSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "sleep 300")
    let readTask = Task {
        try await session.readEvent()
    }

    #expect(
        await waitUntil {
            await fixture.transport.activeReceiveCountObserved() > 0
        }
    )
    readTask.cancel()

    let deliveredBytes = Array("delivered-after-cancel".utf8)
    let channelDataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: session.channel.localChannelID,
                data: deliveredBytes
            )
        )
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serializer.serialize(payload: payload)
    }
    let packet = try serializer.serialize(payload: channelDataPayload)
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(bytes: packet, endOfStream: false),
    ])

    do {
        _ = try await readTask.value
        Issue.record("Expected cancelled session read to throw CancellationError")
    } catch {
        #expect(error is CancellationError)
    }

    let nextEvent = try #require(try await session.readEvent())
    guard case let .standardOutput(bytes) = nextEvent else {
        Issue.record("Expected the next session read to receive the routed channel data")
        return
    }
    #expect(bytes == deliveredBytes)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReceiveConnectionMessageCanIgnorePreexistingCancellation()
    async throws
{
    let expectedMessage = SSHConnectionMessage.channelEOF(
        SSHChannelEOFMessage(recipientChannel: 42)
    )
    let packet = try SSHBinaryPacketSerializer().serialize(
        payload: SSHConnectionMessageSerializer().serialize(expectedMessage)
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(bytes: packet, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    let readTask = Task {
        await waitUntilCurrentTaskIsCancelled()
        return try await client.receiveConnectionMessage(
            respectingTransportReceiveCancellation: false
        )
    }
    readTask.cancel()

    #expect(try await readTask.value == expectedMessage)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReceivePacketKeepsEOFWhenIgnoringCancellation() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)

    let readTask = Task {
        await waitUntilCurrentTaskIsCancelled()
        return try await client.receivePacket(
            respectingTransportReceiveCancellation: false
        )
    }
    readTask.cancel()

    do {
        _ = try await readTask.value
        Issue.record("Expected EOF to be preserved while receive cancellation is ignored.")
    } catch {
        #expect(error as? SSHTransportError == .endOfStreamBeforePacket)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientPrepareProtectedReceiveCanIgnoreRekeyWaitCancellation()
    async throws
{
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let gate = AsyncGate()

    let rekeyTask = Task {
        try await client.withTransportRekeyInProgress {
            await gate.wait()
        }
    }
    defer {
        rekeyTask.cancel()
    }

    #expect(
        await waitUntil {
            await client.isTransportRekeyInProgress
        }
    )

    let receiveTask = Task {
        await waitUntilCurrentTaskIsCancelled()
        try await client.prepareProtectedReceive(respectCancellation: false)
        return true
    }
    receiveTask.cancel()
    try await Task.sleep(nanoseconds: 20_000_000)

    await gate.open()
    #expect(try await receiveTask.value)
    try await rekeyTask.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRoutesWindowAdjustWhileIgnoringCancelledSessionRead()
    async throws
{
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
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        channelSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(
        command: "cat",
        localInitialWindowSize: 8,
        localMaximumPacketSize: 32_768
    )
    let baselineSentPayloadCount = await fixture.transport.sentPayloads().count

    let deliveredBytes = Array("ping".utf8)
    let channelDataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: session.channel.localChannelID,
                data: deliveredBytes
            )
        )
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serializer.serialize(payload: payload)
    }
    let packet = try serializer.serialize(payload: channelDataPayload)
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(bytes: packet, endOfStream: false),
    ])

    let readTask = Task {
        await waitUntilCurrentTaskIsCancelled()
        return try await session.readStandardOutputChunk(respectCancellation: false)
    }
    readTask.cancel()

    let readBytes = try #require(try await readTask.value)
    #expect(readBytes == deliveredBytes)
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentPayloadCount + 1
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })

    var windowAdjusts: [SSHChannelWindowAdjustMessage] = []
    while let packet = try parser.nextPacket() {
        if case let .channelWindowAdjust(windowAdjust) =
            try? SSHConnectionMessageParser().parse(packet.payload) {
            windowAdjusts.append(windowAdjust)
        }
    }

    #expect(
        windowAdjusts.contains(
            SSHChannelWindowAdjustMessage(recipientChannel: 82, bytesToAdd: 4)
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadSessionEventCanIgnorePreexistingCancellation()
    async throws
{
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
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let setupPayloads = [
        serviceAcceptPayload,
        authSuccessPayload,
        openConfirmationPayload,
        channelSuccessPayload,
    ]
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "cat")

    let deliveredBytes = Array("event-after-cancel".utf8)
    let channelDataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: session.channel.localChannelID,
                data: deliveredBytes
            )
        )
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serializer.serialize(payload: payload)
    }
    let packet = try serializer.serialize(payload: channelDataPayload)

    let readTask = Task {
        await waitUntilCurrentTaskIsCancelled()
        return try await session.readEvent(respectCancellation: false)
    }
    readTask.cancel()
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(bytes: packet, endOfStream: false),
    ])

    let event = try #require(try await readTask.value)
    #expect(event == .standardOutput(deliveredBytes))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsSFTPOperationWhileWaitingForResponse() async throws {
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
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
        ],
        emptyReceiveBehavior: .delayedEndOfStream(
            delayNanoseconds: 200_000_000,
            ignoreCancellation: true
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    await expectOperationCancellation {
        _ = try await sftpClient.stat("/tmp/test")
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsQueuedInboundPacketReceiveTurnWithoutBlockingNextWaiter()
    async throws
{
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let gate = AsyncGate()

    let holder = Task {
        try await client.acquireInboundPacketReceiveTurn()
        await gate.wait()
        await client.releaseInboundPacketReceiveTurn()
    }
    defer {
        holder.cancel()
    }

    #expect(
        await waitUntil {
            await client.isReceivingInboundPacket
        }
    )

    await expectOperationCancellation {
        try await client.acquireInboundPacketReceiveTurn()
    }

    let nextWaiter = Task {
        try await client.acquireInboundPacketReceiveTurn()
        await client.releaseInboundPacketReceiveTurn()
        return true
    }

    await gate.open()
    #expect(try await nextWaiter.value)
    try await holder.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsWaitForConnectionMessageWaiterProgress() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let gate = AsyncGate()

    let blocker = Task {
        try await client.withConnectionMessageWaiterTurn {
            await gate.wait()
        }
    }
    defer {
        blocker.cancel()
    }

    #expect(
        await waitUntil {
            await client.activeConnectionMessageWaiterCount == 1
        }
    )

    await expectOperationCancellation {
        try await client.waitForConnectionMessageWaiterProgress()
    }

    await gate.open()
    try await blocker.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsWaitForTransportRekeyToComplete() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let gate = AsyncGate()

    let blocker = Task {
        try await client.withTransportRekeyInProgress {
            await gate.wait()
        }
    }
    defer {
        blocker.cancel()
    }

    #expect(
        await waitUntil {
            await client.isTransportRekeyInProgress
        }
    )

    await expectOperationCancellation {
        try await client.waitForTransportRekeyToComplete()
    }

    await gate.open()
    try await blocker.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsQueuedOutboundGlobalRequestTurnWithoutBlockingNextWaiter()
    async throws
{
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [],
        emptyReceiveBehavior: .endOfStream
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let gate = AsyncGate()

    let holder = Task {
        try await client.withOutboundGlobalRequestTurn {
            await gate.wait()
        }
    }
    defer {
        holder.cancel()
    }

    #expect(
        await waitUntil {
            await client.isOutboundGlobalRequestInFlight
        }
    )

    await expectOperationCancellation {
        try await client.withOutboundGlobalRequestTurn {}
    }

    let nextWaiter = Task {
        try await client.withOutboundGlobalRequestTurn {}
        return true
    }

    await gate.open()
    #expect(try await nextWaiter.value)
    try await holder.value
}

private actor AsyncGate {
    private var continuations: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            self.continuations.append(continuation)
        }
    }

    func open() {
        let continuations = self.continuations
        self.continuations.removeAll(keepingCapacity: true)
        for continuation in continuations {
            continuation.resume()
        }
    }
}

private func waitUntilCurrentTaskIsCancelled() async {
    while !Task.isCancelled {
        await Task.yield()
    }
}
