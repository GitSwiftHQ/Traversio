// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshClientWritesStandardErrorThroughPublicSessionWrapper() async throws {
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
                senderChannel: 43,
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
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            exitStatusPayload,
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

    let output = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openExec("cat >&2")
        try await session.writeStandardError("client stderr\n")
        try await session.sendEOF()
        return try await session.collectOutputUntilClose()
    }

    #expect(output.standardOutput.isEmpty)
    #expect(output.standardError.isEmpty)
    #expect(output.exitStatus == 0)
    #expect(output.didReceiveEOF)

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

    var extendedDataMessages: [SSHChannelExtendedDataMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelExtendedData.rawValue else {
            continue
        }

        if case let .channelExtendedData(value) =
            try SSHConnectionMessageParser().parse(packet.payload) {
            extendedDataMessages.append(value)
        }
    }

    #expect(
        extendedDataMessages == [
            SSHChannelExtendedDataMessage(
                recipientChannel: 43,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("client stderr\n".utf8)
            )
        ]
    )
}

@Test
func sshClientAdjustsReceiveWindowThroughPublicSessionWrapper() async throws {
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
                senderChannel: 43,
                initialWindowSize: 64,
                maximumPacketSize: 16,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let snapshots = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openExec("cat")
        let beforeAdjust = try await session.channelWindowSnapshot()
        let afterAdjust = try await session.adjustReceiveWindow(by: 7)
        return (beforeAdjust, afterAdjust)
    }

    #expect(snapshots.0.receiveWindowByteCount == 1_048_576)
    #expect(snapshots.0.sendWindowByteCount == 64)
    #expect(snapshots.0.sendMaximumPacketByteCount == 16)
    #expect(snapshots.1.receiveWindowByteCount == 1_048_583)

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

    var windowAdjusts: [SSHChannelWindowAdjustMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelWindowAdjust.rawValue else {
            continue
        }

        if case let .channelWindowAdjust(value) =
            try SSHConnectionMessageParser().parse(packet.payload) {
            windowAdjusts.append(value)
        }
    }

    #expect(
        windowAdjusts == [
            SSHChannelWindowAdjustMessage(
                recipientChannel: 43,
                bytesToAdd: 7
            )
        ]
    )
}
