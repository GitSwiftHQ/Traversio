// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientBatchesReceiveWindowCreditAtOpenSSHPacketCadence() async {
    let transport = ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    let client = SSHTransportProtocolClient(transport: transport)

    #expect(
        await client.receiveWindowReplenishThreshold(for: 1_048_576) == 98_305
    )
    #expect(
        await client.receiveWindowReplenishThreshold(for: 2 * 1_024 * 1_024) == 98_305
    )
    #expect(
        await client.receiveWindowReplenishThreshold(
            for: 1_048_576,
            maximumPacketSize: 64
        ) == 193
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sessionReceiveWindowReturnsConsumedCreditAfterPacketCadenceIsCrossed() throws {
    var state = SSHSessionReceiveWindowState(
        initialWindowSize: 2 * 1_024 * 1_024,
        replenishThreshold: 98_305
    )
    try state.recordReceivedBytes(
        byteCount: 200 * 1_024,
        localChannelID: 7,
        remoteChannelID: 70
    )

    let adjustment = try state.replenishForConsumedBytes(
        byteCount: 1,
        localChannelID: 7,
        remoteChannelID: 70
    )

    #expect(
        adjustment == SSHChannelWindowAdjustMessage(
            recipientChannel: 70,
            bytesToAdd: 1
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientUsesChunkBufferOnlyAfterStandardOutputChunkReaderStarts() async throws {
    let stdout = Array("streamed stdout".utf8)
    let fixture = try await makeActivatedExecFixture(
        serverPayloadsAfterExecSuccess: [
            try SSHConnectionMessageSerializer().serialize(
                .channelData(SSHChannelDataMessage(recipientChannel: 0, data: stdout))
            ),
        ]
    )

    let session = try await fixture.openExecSession()

    #expect(try await session.readStandardOutputChunk() == stdout)

    let storedState = await fixture.client.managedSessionStates[0]
    let state = try #require(storedState)
    #expect(state.outputState.bufferingMode == .standardOutputChunks)
    #expect(state.outputState.standardOutput.isEmpty)
    #expect(state.outputState.pendingEvents.isEmpty)
    #expect(state.outputState.unreadStandardOutput.isEmpty)

    try await session.close()
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientUsesEventBufferOnlyAfterEventReaderStarts() async throws {
    let stdout = Array("event stdout".utf8)
    let fixture = try await makeActivatedExecFixture(
        serverPayloadsAfterExecSuccess: [
            try SSHConnectionMessageSerializer().serialize(
                .channelData(SSHChannelDataMessage(recipientChannel: 0, data: stdout))
            ),
        ]
    )

    let session = try await fixture.openExecSession()

    #expect(try await session.readEvent() == .standardOutput(stdout))

    let storedState = await fixture.client.managedSessionStates[0]
    let state = try #require(storedState)
    #expect(state.outputState.bufferingMode == .events)
    #expect(state.outputState.standardOutput.isEmpty)
    #expect(state.outputState.unreadStandardOutput.isEmpty)
    #expect(state.outputState.standardError.isEmpty)
    #expect(state.outputState.pendingEvents.isEmpty)

    try await session.close()
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRemovesExecStateAfterStandardOutputChunkStreamEnds() async throws {
    let stdout = Array("chunk terminal stdout".utf8)
    let fixture = try await makeActivatedExecFixture(
        serverPayloadsAfterExecSuccess: makeTerminalSessionPayloads(stdout: stdout)
    )
    let session = try await fixture.openExecSession()

    #expect(try await session.readStandardOutputChunk() == stdout)
    #expect(try await session.readStandardOutputChunk() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRemovesExecStateAfterEventStreamEnds() async throws {
    let stdout = Array("event terminal stdout".utf8)
    let fixture = try await makeActivatedExecFixture(
        serverPayloadsAfterExecSuccess: makeTerminalSessionPayloads(stdout: stdout)
    )
    let session = try await fixture.openExecSession()

    #expect(try await session.readEvent() == .standardOutput(stdout))
    #expect(try await session.readEvent() == .endOfFile)
    #expect(try await session.readEvent() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRemovesDirectTCPIPStateAfterReadChunkStreamEnds() async throws {
    let inboundData = Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
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
        ] + makeTerminalSessionPayloads(stdout: inboundData)
    )

    _ = try await fixture.client.authenticatePassword(username: "root", password: "s3cr3t")
    let channel = try await fixture.client.openDirectTCPIPChannel(
        target: SSHSocketEndpoint(host: "db.internal", port: 5432),
        originator: SSHSocketEndpoint(host: "127.0.0.1", port: 61321)
    )

    #expect(try await channel.readChunk() == inboundData)
    #expect(try await channel.readChunk() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDoesNotReplenishBufferedChannelUntilItsConsumerReads() async throws {
    // Two exec channels share one connection. Channel B's consumer never reads while
    // channel A's reader pumps the shared receive turn (which routes B's data into B's
    // buffer). The fix requires that routing B's data only decrements B's receive window
    // and buffers the bytes: B's window must NOT be replenished until B's own consumer
    // drains the buffer. A small initial window (64) with a 33-byte replenish threshold
    // lets test-sized payloads exercise the batching that the production 1 MiB window uses.
    let channelAStdout = Array(repeating: UInt8(0x41), count: 40)
    let channelBFirstStdout = Array(repeating: UInt8(0x42), count: 40)
    let channelBSecondStdout = Array(repeating: UInt8(0x43), count: 24)
    let channelBBufferedStdout = channelBFirstStdout + channelBSecondStdout

    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let channelAOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 90,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelAChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let channelBOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 91,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelBChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let channelBFirstStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(SSHChannelDataMessage(recipientChannel: 1, data: channelBFirstStdout))
    )
    let channelBSecondStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(SSHChannelDataMessage(recipientChannel: 1, data: channelBSecondStdout))
    )
    let channelAStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(SSHChannelDataMessage(recipientChannel: 0, data: channelAStdout))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            channelAOpenConfirmationPayload,
            channelAChannelSuccessPayload,
            channelBOpenConfirmationPayload,
            channelBChannelSuccessPayload,
            // Channel B's data arrives before channel A's, so channel A's reader routes both
            // B chunks into B's buffer before it finds its own chunk.
            channelBFirstStdoutPayload,
            channelBSecondStdoutPayload,
            channelAStdoutPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(username: "root", password: "s3cr3t")

    let sessionA = try await fixture.client.openExecSession(
        command: "channel-a",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )
    let sessionB = try await fixture.client.openExecSession(
        command: "channel-b",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )

    // Reading channel A pumps the shared receive turn, which routes both of channel B's
    // chunks into B's buffer along the way, then returns A's own chunk.
    #expect(try await sessionA.readStandardOutputChunk() == channelAStdout)

    // Channel B received a full window (40 + 24 == 64 bytes) but its consumer has not read,
    // so its advertised window must have drained to zero and stayed there: no WINDOW_ADJUST
    // was emitted on receipt. The bytes are buffered, not dropped.
    let bufferedBState = try #require(await fixture.client.managedSessionStates[1])
    #expect(bufferedBState.receiveWindowState.remainingWindowSize == 0)
    #expect(bufferedBState.outputState.unreadStandardOutput == channelBBufferedStdout)

    // Channel A consumed its 40-byte chunk, which crossed the 33-byte threshold and released
    // window back to the peer, so A's window returned to its initial size.
    let drainedAState = try #require(await fixture.client.managedSessionStates[0])
    #expect(drainedAState.receiveWindowState.remainingWindowSize == 64)

    // Confirm on the wire: while B's consumer was idle, no WINDOW_ADJUST was sent for B.
    let sentBeforeReadingB = await fixture.transport.sentPayloads()
    #expect(
        try windowAdjustmentBytesToAdd(
            forRecipientChannel: 91,
            inSentPayloads: sentBeforeReadingB,
            activation: fixture.activation
        ).isEmpty
    )

    // Now channel B's consumer reads. Draining the buffer is the consumption event that
    // finally replenishes B's window, and a single WINDOW_ADJUST covers the drained bytes.
    #expect(try await sessionB.readStandardOutputChunk() == channelBBufferedStdout)
    let replenishedBState = try #require(await fixture.client.managedSessionStates[1])
    #expect(replenishedBState.receiveWindowState.remainingWindowSize == 64)

    let sentAfterReadingB = await fixture.transport.sentPayloads()
    #expect(
        try windowAdjustmentBytesToAdd(
            forRecipientChannel: 91,
            inSentPayloads: sentAfterReadingB,
            activation: fixture.activation
        ) == [64]
    )
}

// A transcript collector activated on a channel whose full initial window is already
// buffered (routed there by another channel's reader) must credit those bytes BEFORE
// waiting for the next inbound message: the peer is window-blocked and the connection is
// otherwise quiescent, so no further message can arrive until the WINDOW_ADJUST goes out.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReplenishesPreBufferedTranscriptWindowBeforeWaitingForMessages() async throws {
    let channelAStdout = Array(repeating: UInt8(0x41), count: 40)
    let channelBStdout = Array(repeating: UInt8(0x42), count: 64)
    let setupPayloads = try makeTwoChannelSetupPayloads(
        channelBStdout: channelBStdout,
        channelAStdout: channelAStdout
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: setupPayloads,
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(username: "root", password: "s3cr3t")
    let sessionA = try await fixture.client.openExecSession(
        command: "channel-a",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )
    let sessionB = try await fixture.client.openExecSession(
        command: "channel-b",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )

    // Reading channel A routes channel B's full 64-byte window into B's buffer.
    #expect(try await sessionA.readStandardOutputChunk() == channelAStdout)
    let bufferedBState = try #require(await fixture.client.managedSessionStates[1])
    #expect(bufferedBState.receiveWindowState.remainingWindowSize == 0)

    let collectTask = Task {
        try await sessionB.collectOutputUntilClose()
    }

    // No further inbound message is queued: the credit must appear on the wire from the
    // transcript loop's own first turn, before it blocks on the next message.
    var sawWindowAdjust = false
    for _ in 0..<400 {
        let sent = await fixture.transport.sentPayloads()
        if try windowAdjustmentBytesToAdd(
            forRecipientChannel: 91,
            inSentPayloads: sent,
            activation: fixture.activation
        ) == [64] {
            sawWindowAdjust = true
            break
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(sawWindowAdjust)

    // Only now let the channel finish, and confirm the transcript kept every buffered byte.
    var serverSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    for payload in setupPayloads {
        _ = try serverSerializer.serialize(payload: payload)
    }
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    await fixture.transport.appendReceiveChunks([
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: eofPayload),
            endOfStream: false
        ),
        SSHByteStreamChunk(
            bytes: try serverSerializer.serialize(payload: closePayload),
            endOfStream: false
        ),
    ])

    let transcript = try await collectTask.value
    #expect(transcript.standardOutput == channelBStdout)
    #expect(transcript.didReceiveEOF)
}

// Cancelling a chunk read after it has drained its buffered chunk — while the window-credit
// send is still queued behind another in-flight packet — must neither discard the drained
// chunk nor lose the WINDOW_ADJUST: the drain is already persisted, so an interrupted send
// would silently desynchronize the local and peer window views.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelledChunkReadStillDeliversChunkAndWindowAdjust() async throws {
    let channelAStdout = Array(repeating: UInt8(0x41), count: 40)
    let channelBStdout = Array(repeating: UInt8(0x42), count: 64)
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: try makeTwoChannelSetupPayloads(
            channelBStdout: channelBStdout,
            channelAStdout: channelAStdout
        ),
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(username: "root", password: "s3cr3t")
    let sessionA = try await fixture.client.openExecSession(
        command: "channel-a",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )
    let sessionB = try await fixture.client.openExecSession(
        command: "channel-b",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )
    #expect(try await sessionA.readStandardOutputChunk() == channelAStdout)

    // Occupy the single outbound packet-send turn with a slow unrelated packet so the
    // chunk read's window-credit send has to queue behind it.
    await fixture.transport.setSendDelayNanoseconds(800_000_000)
    let turnHolder = Task {
        try? await fixture.client.sendConnectionMessage(
            .channelData(SSHChannelDataMessage(recipientChannel: 90, data: [0x2e]))
        )
    }
    var turnHolderSending = false
    for _ in 0..<400 {
        if await fixture.transport.activeSendCountObserved() >= 1 {
            turnHolderSending = true
            break
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(turnHolderSending)

    let readTask = Task {
        try await sessionB.readStandardOutputChunk()
    }
    // Wait for the drain to be persisted (the buffered chunk left the session state); the
    // read is now at or past its window-credit send, queued behind the turn holder.
    var drainPersisted = false
    for _ in 0..<400 {
        if let state = await fixture.client.managedSessionStates[1],
           state.outputState.unreadStandardOutput.isEmpty {
            drainPersisted = true
            break
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    #expect(drainPersisted)

    readTask.cancel()

    // The already-drained chunk must still be delivered and its credit must reach the wire.
    #expect(try await readTask.value == channelBStdout)
    let sent = await fixture.transport.sentPayloads()
    #expect(
        try windowAdjustmentBytesToAdd(
            forRecipientChannel: 91,
            inSentPayloads: sent,
            activation: fixture.activation
        ) == [64]
    )
    _ = await turnHolder.value
}

// Shared two-channel arrangement: channel B's full 64-byte initial window arrives before
// channel A's data, so channel A's reader routes B's bytes into B's buffer.
private func makeTwoChannelSetupPayloads(
    channelBStdout: [UInt8],
    channelAStdout: [UInt8]
) throws -> [[UInt8]] {
    [
        try SSHTransportMessageSerializer().serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        ),
        try SSHUserAuthenticationMessageSerializer().serialize(
            .success(SSHUserAuthenticationSuccessMessage())
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: 0,
                    senderChannel: 90,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: 1,
                    senderChannel: 91,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelData(SSHChannelDataMessage(recipientChannel: 1, data: channelBStdout))
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelData(SSHChannelDataMessage(recipientChannel: 0, data: channelAStdout))
        ),
    ]
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func windowAdjustmentBytesToAdd(
    forRecipientChannel recipientChannel: UInt32,
    inSentPayloads sentPayloads: [[UInt8]],
    activation: SSHCurve25519TransportActivation
) throws -> [UInt32] {
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: activation.negotiation.algorithms,
        keyMaterial: activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })

    var bytesToAdd: [UInt32] = []
    while let packet = try parser.nextPacket() {
        guard let message = try? SSHConnectionMessageParser().parse(packet.payload),
              case let .channelWindowAdjust(adjust) = message,
              adjust.recipientChannel == recipientChannel else {
            continue
        }
        bytesToAdd.append(adjust.bytesToAdd)
    }
    return bytesToAdd
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeActivatedExecFixture(
    serverPayloadsAfterExecSuccess: [[UInt8]]
) async throws -> (
    client: SSHTransportProtocolClient,
    transport: ProtocolClientMockSSHByteStreamTransport,
    activation: SSHCurve25519TransportActivation,
    openExecSession: () async throws -> SSHSessionHandle
) {
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
                senderChannel: 61,
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
        ] + serverPayloadsAfterExecSuccess
    )

    _ = try await fixture.client.authenticatePassword(username: "root", password: "s3cr3t")

    return (
        client: fixture.client,
        transport: fixture.transport,
        activation: fixture.activation,
        openExecSession: {
            try await fixture.client.openExecSession(command: "printf test")
        }
    )
}

private func makeTerminalSessionPayloads(stdout: [UInt8]) throws -> [[UInt8]] {
    [
        try SSHConnectionMessageSerializer().serialize(
            .channelData(SSHChannelDataMessage(recipientChannel: 0, data: stdout))
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
        ),
    ]
}
