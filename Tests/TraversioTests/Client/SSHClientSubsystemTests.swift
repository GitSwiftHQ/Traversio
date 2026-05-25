// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshClientOpensSubsystemSessionAndExpiresWrapperScope() async throws {
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
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let environmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let subsystemSuccessPayload = try SSHConnectionMessageSerializer().serialize(
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
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            environmentSuccessPayload,
            subsystemSuccessPayload,
            stdoutPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let environmentVariable = SSHSessionEnvironmentVariable(
        name: "LANG",
        value: "en_US.UTF-8"
    )

    var escapedSession: SSHSession?
    let events: [SSHSessionEvent] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openSubsystem(
            "netconf",
            environment: [environmentVariable]
        )
        escapedSession = session

        var streamedEvents: [SSHSessionEvent] = []
        for try await event in session.events {
            streamedEvents.append(event)
        }
        return streamedEvents
    }

    #expect(
        events == [
            .standardOutput(Array("ready\n".utf8)),
            .endOfFile,
        ]
    )

    let session = try #require(escapedSession)
    do {
        _ = try await session.nextEvent()
        Issue.record("Expected subsystem session wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

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

    var channelRequests: [SSHChannelRequestMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelRequest.rawValue else {
            continue
        }

        let message = try SSHConnectionMessageParser().parse(packet.payload)
        if case let .channelRequest(value) = message {
            channelRequests.append(value)
        }
    }

    #expect(channelRequests.count == 2)
    #expect(
        try SSHSessionRequestCoder().parseEnvironmentRequest(from: channelRequests[0])
            == environmentVariable
    )
    #expect(
        try SSHSessionRequestCoder().parseSubsystemRequest(from: channelRequests[1])
            == "netconf"
    )
}
