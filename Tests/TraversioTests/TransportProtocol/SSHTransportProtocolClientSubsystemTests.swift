// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func transportProtocolClientSendsEnvironmentBeforeSubsystemRequest() async throws {
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
    let environmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let subsystemSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            environmentSuccessPayload,
            subsystemSuccessPayload,
        ]
    )
    let environmentVariable = SSHSessionEnvironmentVariable(
        name: "LANG",
        value: "en_US.UTF-8"
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openSubsystemSession(
        subsystem: "netconf",
        environment: [environmentVariable]
    )
    try await session.close()

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let environmentPacket = try #require(try parser.nextPacket())
    let subsystemPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

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
    #expect(
        try SSHConnectionMessageParser().parse(openPacket.payload)
            == .channelOpen(
                SSHChannelOpenMessage(
                    channelType: "session",
                    senderChannel: 0,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
    )

    let environmentRequest = try #require(
        try SSHConnectionMessageParser().parse(environmentPacket.payload).channelRequestValue
    )
    #expect(
        try SSHSessionRequestCoder().parseEnvironmentRequest(from: environmentRequest)
            == environmentVariable
    )

    let subsystemRequest = try #require(
        try SSHConnectionMessageParser().parse(subsystemPacket.payload).channelRequestValue
    )
    #expect(try SSHSessionRequestCoder().parseSubsystemRequest(from: subsystemRequest) == "netconf")

    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 64)
            )
    )
}

private extension SSHConnectionMessage {
    var channelRequestValue: SSHChannelRequestMessage? {
        if case let .channelRequest(value) = self {
            return value
        }
        return nil
    }
}
