// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

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
    // drains the buffer. A small initial window (64) with a 32-byte replenish threshold
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

    // Channel A consumed its 40-byte chunk, which crossed the 32-byte threshold and released
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
