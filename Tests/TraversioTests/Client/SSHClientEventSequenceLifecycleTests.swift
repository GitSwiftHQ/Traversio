// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshClientSessionEventSequenceEarlyExitBestEffortClosesExecChannel() async throws {
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
                senderChannel: 62,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("ready\n".utf8)
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            stdoutPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let session = try await connection.openExec("printf ready")
    let baselineSentCount = await transport.sentPayloads().count

    try await consumeFirstSessionEventAndExit(session)

    try await expectLastClientConnectionMessage(
        on: transport,
        baselineSentCount: baselineSentCount,
        expectedMessage: .channelClose(
            SSHChannelCloseMessage(recipientChannel: 62)
        )
    )

    await connection.close()
}

@Test
func sshClientDirectTCPIPEventSequenceEarlyExitBestEffortClosesChannel() async throws {
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
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("PONG".utf8)
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let channel = try await connection.openDirectTCPIPChannel(
        targetHost: "db.internal",
        targetPort: 5432,
        originatorAddress: "127.0.0.1",
        originatorPort: 61001
    )
    let baselineSentCount = await transport.sentPayloads().count

    try await consumeFirstTCPIPEventAndExit(channel)

    try await expectLastClientConnectionMessage(
        on: transport,
        baselineSentCount: baselineSentCount,
        expectedMessage: .channelClose(
            SSHChannelCloseMessage(recipientChannel: 56)
        )
    )

    await connection.close()
}

private func consumeFirstSessionEventAndExit(_ session: SSHSession) async throws {
    for try await event in session.events {
        #expect(event == .standardOutput(Array("ready\n".utf8)))
        break
    }
}

private func consumeFirstTCPIPEventAndExit(_ channel: SSHDirectTCPIPChannel) async throws {
    for try await event in channel.events {
        #expect(event == .data(Array("PONG".utf8)))
        break
    }
}

private func expectLastClientConnectionMessage(
    on transport: ConnectionFixtureMockSSHByteStreamTransport,
    baselineSentCount: Int,
    expectedMessage: SSHConnectionMessage
) async throws {
    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    let lastPacket = try #require(packets.last)
    #expect(
        try SSHConnectionMessageParser().parse(lastPacket.payload) == expectedMessage
    )
}
