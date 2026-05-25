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
