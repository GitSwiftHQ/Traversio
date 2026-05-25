// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadFileReturnsBytesAndClosesHandle() async throws {
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
                senderChannel: 89,
                initialWindowSize: 256,
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
    let fileHandle = SSHSFTPHandle(bytes: [0xfa, 0xce, 0xb0, 0x0c])
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
    let dataPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .data(
                SSHSFTPDataMessage(
                    requestID: 1,
                    data: Array("hello".utf8)
                )
            )
        )
    )
    let endOfFilePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 2,
                    statusCode: .endOfFile,
                    errorMessage: "EOF",
                    languageTag: ""
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
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: dataPacket
            )
        )
    )
    let endOfFilePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: endOfFilePacket
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
            dataPayload,
            endOfFilePayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let data = try await sftpClient.readFile("/root/.profile", chunkSize: 8)

    #expect(data == Array("hello".utf8))

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
    let firstReadFilePacket = try #require(try parser.nextPacket())
    let secondReadFilePacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/.profile",
                    pflags: [.read],
                    attributes: .empty
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: firstReadFilePacket)
            == .readFile(
                SSHSFTPReadFileMessage(
                    requestID: 1,
                    handle: fileHandle,
                    offset: 0,
                    length: 8
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: secondReadFilePacket)
            == .readFile(
                SSHSFTPReadFileMessage(
                    requestID: 2,
                    handle: fileHandle,
                    offset: 5,
                    length: 8
                )
            )
    )
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
func transportProtocolClientReadFileClosesHandleWhenReadFails() async throws {
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
                senderChannel: 90,
                initialWindowSize: 256,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x55, 0x66, 0x77, 0x88])
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
    let readFailurePacket = try SSHSFTPPacketSerializer().serialize(
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
    let readFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: readFailurePacket
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
            readFailurePayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        _ = try await sftpClient.readFile("/root/secret.txt", chunkSize: 8)
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
    let readFilePacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/secret.txt",
                    pflags: [.read],
                    attributes: .empty
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: readFilePacket)
            == .readFile(
                SSHSFTPReadFileMessage(
                    requestID: 1,
                    handle: fileHandle,
                    offset: 0,
                    length: 8
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

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFStatReturnsAttributesForOpenedFileHandle() async throws {
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
                senderChannel: 91,
                initialWindowSize: 256,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
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
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag |
            SSHSFTPFileAttributes.userIDAndGroupIDFlag |
            SSHSFTPFileAttributes.permissionsFlag,
        size: 161,
        userID: 0,
        groupID: 0,
        permissions: 0o644,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let attributesPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: 1,
                    attributes: attributes
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
    let attributesPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: attributesPacket
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
            attributesPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let handle = try await sftpClient.openFile("/root/.profile")
    let receivedAttributes = try await sftpClient.fstat(handle: handle)

    #expect(receivedAttributes == attributes)

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
    let fstatPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openFilePacket)
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/.profile",
                    pflags: [.read],
                    attributes: .empty
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: fstatPacket)
            == .fstat(
                SSHSFTPFStatMessage(
                    requestID: 1,
                    handle: fileHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFStatSurfacesStatusFailure() async throws {
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
                senderChannel: 92,
                initialWindowSize: 256,
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
    let fileHandle = SSHSFTPHandle(bytes: [0x55, 0x44, 0x33, 0x22])
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
    let statusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .failure,
                    errorMessage: "fstat failed",
                    languageTag: ""
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
    let statusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: statusPacket
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
            statusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let handle = try await sftpClient.openFile("/root/.profile")

    do {
        _ = try await sftpClient.fstat(handle: handle)
        Issue.record("Expected SFTP status error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .status(
                    SSHSFTPStatusMessage(
                        requestID: 1,
                        statusCode: .failure,
                        errorMessage: "fstat failed",
                        languageTag: ""
                    )
                )
        )
    }
}
