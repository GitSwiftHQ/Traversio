// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientListDirectoryReturnsEntriesAndClosesHandle() async throws {
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
                senderChannel: 87,
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
    let directoryHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let handlePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: directoryHandle
                )
            )
        )
    )
    let namePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .name(
                SSHSFTPNameMessage(
                    requestID: 1,
                    entries: [
                        SSHSFTPNameEntry(
                            filename: "alpha.txt",
                            longName: "alpha.txt",
                            attributes: SSHSFTPFileAttributes(
                                flags: SSHSFTPFileAttributes.sizeFlag,
                                size: 12,
                                userID: nil,
                                groupID: nil,
                                permissions: nil,
                                accessTime: nil,
                                modificationTime: nil,
                                extensions: []
                            )
                        ),
                        SSHSFTPNameEntry(
                            filename: "beta.log",
                            longName: "beta.log",
                            attributes: .empty
                        )
                    ]
                )
            )
        )
    )
    let endOfDirectoryPacket = try SSHSFTPPacketSerializer().serialize(
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
    let namePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: namePacket
            )
        )
    )
    let endOfDirectoryPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: endOfDirectoryPacket
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
            namePayload,
            endOfDirectoryPayload,
            closeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let entries = try await sftpClient.listDirectory("/root")

    #expect(
        entries == [
            SSHSFTPNameEntry(
                filename: "alpha.txt",
                longName: "alpha.txt",
                attributes: SSHSFTPFileAttributes(
                    flags: SSHSFTPFileAttributes.sizeFlag,
                    size: 12,
                    userID: nil,
                    groupID: nil,
                    permissions: nil,
                    accessTime: nil,
                    modificationTime: nil,
                    extensions: []
                )
            ),
            SSHSFTPNameEntry(
                filename: "beta.log",
                longName: "beta.log",
                attributes: .empty
            )
        ]
    )

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
    let openDirectoryPacket = try #require(try parser.nextPacket())
    let firstReadDirectoryPacket = try #require(try parser.nextPacket())
    let secondReadDirectoryPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openDirectoryPacket)
            == .openDirectory(
                SSHSFTPOpenDirectoryMessage(
                    requestID: 0,
                    path: "/root"
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: firstReadDirectoryPacket)
            == .readDirectory(
                SSHSFTPReadDirectoryMessage(
                    requestID: 1,
                    handle: directoryHandle
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: secondReadDirectoryPacket)
            == .readDirectory(
                SSHSFTPReadDirectoryMessage(
                    requestID: 2,
                    handle: directoryHandle
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: closePacket)
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 3,
                    handle: directoryHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientListDirectoryClosesHandleWhenReadDirectoryFails() async throws {
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
                senderChannel: 88,
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
    let directoryHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
    let handlePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: directoryHandle
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
        _ = try await sftpClient.listDirectory("/restricted")
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
    let openDirectoryPacket = try #require(try parser.nextPacket())
    let readDirectoryPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: openDirectoryPacket)
            == .openDirectory(
                SSHSFTPOpenDirectoryMessage(
                    requestID: 0,
                    path: "/restricted"
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: readDirectoryPacket)
            == .readDirectory(
                SSHSFTPReadDirectoryMessage(
                    requestID: 1,
                    handle: directoryHandle
                )
            )
    )
    #expect(
        try parseSFTPMessage(from: closePacket)
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 2,
                    handle: directoryHandle
                )
            )
    )
}
