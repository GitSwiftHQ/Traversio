// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientWriteFileSendsWriteRequestsAndClosesHandle() async throws {
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
                senderChannel: 93,
                initialWindowSize: 512,
                maximumPacketSize: 128,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x01, 0x23, 0x45, 0x67])
    let handlePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            )
        )
    )
    let firstWriteStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            )
        )
    )
    let secondWriteStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 2,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            )
        )
    )
    let thirdWriteStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 3,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            )
        )
    )
    let closeStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 4,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
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
    let handlePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: handlePacket
            )
        )
    )
    let firstWriteStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: firstWriteStatusPacket
            )
        )
    )
    let secondWriteStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: secondWriteStatusPacket
            )
        )
    )
    let thirdWriteStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: thirdWriteStatusPacket
            )
        )
    )
    let closeStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: closeStatusPacket
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
            handlePayload,
            firstWriteStatusPayload,
            secondWriteStatusPayload,
            thirdWriteStatusPayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.writeFile(
        "/root/output.txt",
        data: Array("hello world".utf8),
        chunkSize: 5
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1,
        maximumPacketSize: 1_048_576
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let openFilePacket = try #require(try parser.nextPacket())
    let firstWritePacket = try #require(try parser.nextPacket())
    let secondWritePacket = try #require(try parser.nextPacket())
    let thirdWritePacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/output.txt",
                    pflags: [.write, .create, .truncate],
                    attributes: .empty
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: firstWritePacket)
            == .writeFile(
                SSHSFTPWriteFileMessage(
                    requestID: 1,
                    handle: fileHandle,
                    offset: 0,
                    data: Array("hello".utf8)
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: secondWritePacket)
            == .writeFile(
                SSHSFTPWriteFileMessage(
                    requestID: 2,
                    handle: fileHandle,
                    offset: 5,
                    data: Array(" worl".utf8)
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: thirdWritePacket)
            == .writeFile(
                SSHSFTPWriteFileMessage(
                    requestID: 3,
                    handle: fileHandle,
                    offset: 10,
                    data: Array("d".utf8)
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: closePacket)
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 4,
                    handle: fileHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientWriteFileClampsOversizedChunksToSafePacketPayloads() async throws {
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
                senderChannel: 193,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 1_048_576,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x01, 0x23, 0x45, 0x67])
    let handlePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            )
        )
    )
    let firstWriteStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            )
        )
    )
    let secondWriteStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 2,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            )
        )
    )
    let closeStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 3,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
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
    let handlePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: handlePacket
            )
        )
    )
    let firstWriteStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: firstWriteStatusPacket
            )
        )
    )
    let secondWriteStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: secondWriteStatusPacket
            )
        )
    )
    let closeStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: closeStatusPacket
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
            handlePayload,
            firstWriteStatusPayload,
            secondWriteStatusPayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let safeChunkSize = Int(SSHSFTPPacketSerializer.defaultMaximumPacketLength) - (1 + 4 + 4 + fileHandle.bytes.count + 8 + 4)
    let payload = Array(repeating: UInt8(ascii: "a"), count: safeChunkSize + 8)
    try await sftpClient.writeFile(
        "/root/output.txt",
        data: payload,
        chunkSize: SSHSFTPPacketSerializer.defaultMaximumPacketLength
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1,
        maximumPacketSize: 1_048_576
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let openFilePacket = try #require(try parser.nextPacket())
    let firstWritePacket = try #require(try parser.nextPacket())
    let secondWritePacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/output.txt",
                    pflags: [.write, .create, .truncate],
                    attributes: .empty
                )
            )
    )

    let firstWriteMessage = try parseSFTPMessage(from: firstWritePacket)
    let secondWriteMessage = try parseSFTPMessage(from: secondWritePacket)

    guard case let .writeFile(firstWriteRequest) = firstWriteMessage else {
        Issue.record("Expected first write packet, got \(firstWriteMessage)")
        return
    }
    guard case let .writeFile(secondWriteRequest) = secondWriteMessage else {
        Issue.record("Expected second write packet, got \(secondWriteMessage)")
        return
    }

    #expect(firstWriteRequest.requestID == 1)
    #expect(firstWriteRequest.handle == fileHandle)
    #expect(firstWriteRequest.offset == 0)
    #expect(firstWriteRequest.data.count == safeChunkSize)
    #expect(firstWriteRequest.data.allSatisfy { $0 == UInt8(ascii: "a") })

    #expect(secondWriteRequest.requestID == 2)
    #expect(secondWriteRequest.handle == fileHandle)
    #expect(secondWriteRequest.offset == UInt64(safeChunkSize))
    #expect(secondWriteRequest.data.count == 8)
    #expect(secondWriteRequest.data.allSatisfy { $0 == UInt8(ascii: "a") })

    #expect(
        try parseSFTPMessage(from: closePacket)
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 3,
                    handle: fileHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientWriteFileClosesHandleWhenWriteFails() async throws {
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
                senderChannel: 94,
                initialWindowSize: 512,
                maximumPacketSize: 128,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x89, 0xab, 0xcd, 0xef])
    let handlePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            )
        )
    )
    let writeFailurePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .permissionDenied,
                    errorMessage: "Permission denied",
                    languageTag: ""
                )
            )
        )
    )
    let closeStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 2,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
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
    let handlePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: handlePacket
            )
        )
    )
    let writeFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: writeFailurePacket
            )
        )
    )
    let closeStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: closeStatusPacket
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
            handlePayload,
            writeFailurePayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        try await sftpClient.writeFile(
            "/root/output.txt",
            data: Array("nope".utf8),
            chunkSize: 8
        )
        Issue.record("Expected SFTP status error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .status(
                    SSHSFTPStatusMessage(
                        requestID: 1,
                        statusCode: .permissionDenied,
                        errorMessage: "Permission denied",
                        languageTag: ""
                    )
                )
        )
    }

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let openFilePacket = try #require(try parser.nextPacket())
    let writeFilePacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/output.txt",
                    pflags: [.write, .create, .truncate],
                    attributes: .empty
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: writeFilePacket)
            == .writeFile(
                SSHSFTPWriteFileMessage(
                    requestID: 1,
                    handle: fileHandle,
                    offset: 0,
                    data: Array("nope".utf8)
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: closePacket)
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 2,
                    handle: fileHandle
                )
            )
    )
}
