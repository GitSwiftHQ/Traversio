// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshConnectionReceiveSCPFileReadsSingleRegularFile() async throws {
    let contents = Array("hello scp\n".utf8)
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: try makeSCPAuthenticatedExecPayloads(
            channelPayloads: [
                makeChannelDataPayload("C0644 \(contents.count) fixture.txt\n"),
                makeChannelDataPayload(contents),
                makeChannelDataPayload([0]),
                makeExitStatusPayload(0),
                makeChannelEOFPayload(),
                makeChannelClosePayload(),
            ]
        )
    )

    let received = try await SSHClient.withConnection(
        configuration: makeSCPTestConfiguration(),
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.receiveSCPFile("/tmp/fixture.txt")
    }

    #expect(received.remotePath == "/tmp/fixture.txt")
    #expect(received.fileName == "fixture.txt")
    #expect(received.permissions == 0o644)
    #expect(received.byteCount == UInt64(contents.count))
    #expect(received.contents == contents)
    #expect(received.exitStatus == 0)

    let sentMessages = try await sentConnectionMessages(from: transport)
    let execCommands = try sentMessages.compactMap { message -> String? in
        guard case let .channelRequest(request) = message,
              request.requestType == "exec" else {
            return nil
        }
        return try SSHSessionRequestCoder().parseExecCommand(from: request)
    }
    let dataWrites = sentMessages.compactMap { message -> [UInt8]? in
        guard case let .channelData(data) = message else {
            return nil
        }
        return data.data
    }

    #expect(execCommands == ["scp -f -- '/tmp/fixture.txt'"])
    #expect(dataWrites.filter { $0 == [0] }.count == 3)
}

@Test
func sshConnectionSendSCPFileWritesHeaderDataAndEOF() async throws {
    let contents = Array("hello scp\n".utf8)
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: try makeSCPAuthenticatedExecPayloads(
            channelPayloads: [
                makeChannelDataPayload([0]),
                makeChannelDataPayload([0]),
                makeChannelDataPayload([0]),
                makeExitStatusPayload(0),
                makeChannelEOFPayload(),
                makeChannelClosePayload(),
            ]
        )
    )

    let result = try await SSHClient.withConnection(
        configuration: makeSCPTestConfiguration(),
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.sendSCPFile(
            contents,
            remotePath: "/tmp/upload.txt",
            permissions: 0o640
        )
    }

    #expect(result.remotePath == "/tmp/upload.txt")
    #expect(result.fileName == "upload.txt")
    #expect(result.byteCount == UInt64(contents.count))
    #expect(result.exitStatus == 0)

    let sentMessages = try await sentConnectionMessages(from: transport)
    let execCommands = try sentMessages.compactMap { message -> String? in
        guard case let .channelRequest(request) = message,
              request.requestType == "exec" else {
            return nil
        }
        return try SSHSessionRequestCoder().parseExecCommand(from: request)
    }
    let dataWrites = sentMessages.compactMap { message -> [UInt8]? in
        guard case let .channelData(data) = message else {
            return nil
        }
        return data.data
    }
    let didSendEOF = sentMessages.contains { message in
        guard case .channelEOF = message else {
            return false
        }
        return true
    }

    #expect(execCommands == ["scp -t -- '/tmp/upload.txt'"])
    #expect(dataWrites.contains(Array("C0640 \(contents.count) upload.txt\n".utf8)))
    #expect(dataWrites.contains(contents))
    #expect(dataWrites.contains([0]))
    #expect(didSendEOF)
}

@Test
func sshConnectionReceiveSCPFileRejectsAdditionalControlRecords() async throws {
    let contents = Array("hello scp\n".utf8)
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: try makeSCPAuthenticatedExecPayloads(
            channelPayloads: [
                makeChannelDataPayload("C0644 \(contents.count) fixture.txt\n"),
                makeChannelDataPayload(contents),
                makeChannelDataPayload([0]),
                makeChannelDataPayload("C0644 0 extra.txt\n"),
                makeExitStatusPayload(0),
                makeChannelEOFPayload(),
                makeChannelClosePayload(),
            ]
        )
    )

    await #expect(
        throws: SSHSCPTransferError.unexpectedControlMessage("C0644 0 extra.txt\n")
    ) {
        _ = try await SSHClient.withConnection(
            configuration: makeSCPTestConfiguration(),
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.receiveSCPFile("/tmp/fixture.txt")
        }
    }
}

@Test
func scpProtocolRejectsAmbiguousRemotePathsAndFileNames() throws {
    #expect(throws: SSHSCPTransferError.invalidRemotePath("bad\npath")) {
        _ = try SSHSCPProtocol.makeReceiveCommand(remotePath: "bad\npath")
    }
    #expect(throws: SSHSCPTransferError.invalidFileName("bad/name")) {
        _ = try SSHSCPProtocol.resolveFileName(
            remotePath: "/tmp/file",
            explicitFileName: "bad/name"
        )
    }
    #expect(throws: SSHSCPTransferError.invalidMaximumFileSize(-1)) {
        try SSHSCPProtocol.validateMaximumFileSize(-1)
    }
}

private func makeSCPTestConfiguration() -> SSHClientConfiguration {
    SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
}

private func makeSCPAuthenticatedExecPayloads(
    channelPayloads: [[UInt8]]
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
                    senderChannel: 42,
                    initialWindowSize: 1_048_576,
                    maximumPacketSize: 32_768,
                    channelTypeData: []
                )
            )
        ),
        try SSHConnectionMessageSerializer().serialize(
            .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
        ),
    ] + channelPayloads
}

private func makeChannelDataPayload(_ string: String) throws -> [UInt8] {
    try makeChannelDataPayload(Array(string.utf8))
}

private func makeChannelDataPayload(_ bytes: [UInt8]) throws -> [UInt8] {
    try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: bytes
            )
        )
    )
}

private func makeExitStatusPayload(_ exitStatus: UInt32) throws -> [UInt8] {
    try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(
            recipientChannel: 0,
            exitStatus: exitStatus
        )
    )
}

private func makeChannelEOFPayload() throws -> [UInt8] {
    try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
}

private func makeChannelClosePayload() throws -> [UInt8] {
    try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
}

private func sentConnectionMessages(
    from transport: ConnectionFixtureMockSSHByteStreamTransport
) async throws -> [SSHConnectionMessage] {
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

    var messages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        guard let rawMessageID = packet.payload.first,
              SSHConnectionMessageID(rawValue: rawMessageID) != nil else {
            continue
        }
        messages.append(try SSHConnectionMessageParser().parse(packet.payload))
    }

    return messages
}
