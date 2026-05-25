// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSetAttributesSendsSetStatRequest() async throws {
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.permissionsFlag,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: 0o640,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let fixture = try await makeSFTPFixture(
        senderChannel: 98,
        sftpMessagesAfterVersion: [
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            ),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.setAttributes("/root/example.txt", attributes: attributes)

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.count == 1)
    #expect(
        sentSFTPMessages[0]
            == .setAttributes(
                SSHSFTPSetAttributesMessage(
                    requestID: 0,
                    path: "/root/example.txt",
                    attributes: attributes
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFSetAttributesSendsFSetStatRequest() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag,
        size: 1_024,
        userID: nil,
        groupID: nil,
        permissions: nil,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let fixture = try await makeSFTPFixture(
        senderChannel: 99,
        sftpMessagesAfterVersion: [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            ),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let handle = try await sftpClient.openFile("/root/example.txt", flags: [.write])
    try await sftpClient.setAttributes(handle: handle, attributes: attributes)

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.count == 2)
    #expect(
        sentSFTPMessages[0]
            == .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: 0,
                    path: "/root/example.txt",
                    pflags: [.write],
                    attributes: .empty
                )
            )
    )
    #expect(
        sentSFTPMessages[1]
            == .fsetAttributes(
                SSHSFTPFSetAttributesMessage(
                    requestID: 1,
                    handle: fileHandle,
                    attributes: attributes
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFileSystemAttributesReturnsExtendedReply() async throws {
    let attributes = SSHSFTPFileSystemAttributes(
        blockSize: 4_096,
        fundamentalBlockSize: 4_096,
        totalBlocks: 2_000,
        freeBlocks: 1_000,
        availableBlocks: 900,
        totalFileNodes: 500,
        freeFileNodes: 250,
        availableFileNodes: 200,
        fileSystemID: 77,
        flags: [.readOnly, .noSetUserID],
        maximumFilenameLength: 255
    )
    let fixture = try await makeSFTPFixture(
        senderChannel: 100,
        extensions: [
            SSHSFTPExtension(
                name: "statvfs@openssh.com",
                data: Array("2".utf8)
            ),
        ],
        sftpMessagesAfterVersion: [
            makeExtendedReplyMessage(
                requestID: 0,
                attributes: attributes
            ),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let receivedAttributes = try await sftpClient.fileSystemAttributes("/root")

    #expect(receivedAttributes == attributes)

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.count == 1)
    #expect(
        sentSFTPMessages[0]
            == .statVFS(
                SSHSFTPStatVFSMessage(
                    requestID: 0,
                    path: "/root"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFileSystemAttributesRequiresAdvertisedExtension() async throws {
    let fixture = try await makeSFTPFixture(
        senderChannel: 101,
        sftpMessagesAfterVersion: []
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        _ = try await sftpClient.fileSystemAttributes("/root")
        Issue.record("Expected unsupported extension error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .unsupportedExtendedRequest("statvfs@openssh.com")
        )
    }

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFStatVFSReturnsExtendedReplyForOpenHandle() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let attributes = SSHSFTPFileSystemAttributes(
        blockSize: 8_192,
        fundamentalBlockSize: 4_096,
        totalBlocks: 4_000,
        freeBlocks: 2_500,
        availableBlocks: 2_400,
        totalFileNodes: 1_000,
        freeFileNodes: 900,
        availableFileNodes: 850,
        fileSystemID: 88,
        flags: [],
        maximumFilenameLength: 512
    )
    let fixture = try await makeSFTPFixture(
        senderChannel: 102,
        extensions: [
            SSHSFTPExtension(
                name: "fstatvfs@openssh.com",
                data: Array("2".utf8)
            ),
        ],
        sftpMessagesAfterVersion: [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            ),
            makeExtendedReplyMessage(
                requestID: 1,
                attributes: attributes
            ),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let handle = try await sftpClient.openFile("/root/example.txt")
    let receivedAttributes = try await sftpClient.fileSystemAttributes(handle: handle)

    #expect(receivedAttributes == attributes)

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.count == 2)
    #expect(
        sentSFTPMessages[1]
            == .fstatVFS(
                SSHSFTPFStatVFSMessage(
                    requestID: 1,
                    handle: fileHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientWriteFileWithSyncAfterWriteSendsFSyncBeforeClose() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x41, 0x42, 0x43, 0x44])
    let payload = Array("hello".utf8)
    let fixture = try await makeSFTPFixture(
        senderChannel: 103,
        extensions: [
            SSHSFTPExtension(
                name: "fsync@openssh.com",
                data: Array("1".utf8)
            ),
        ],
        sftpMessagesAfterVersion: [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: 0,
                    handle: fileHandle
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: 1,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: 2,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: 3,
                    statusCode: .ok,
                    errorMessage: nil,
                    languageTag: nil
                )
            ),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.writeFile(
        "/root/output.txt",
        data: payload,
        chunkSize: 64,
        syncAfterWrite: true
    )

    let sentSFTPMessages = try await extractSentSFTPMessages(from: fixture)
    #expect(sentSFTPMessages.count == 4)
    #expect(
        sentSFTPMessages[2]
            == .fsync(
                SSHSFTPFSyncMessage(
                    requestID: 2,
                    handle: fileHandle
                )
            )
    )
    #expect(
        sentSFTPMessages[3]
            == .close(
                SSHSFTPCloseMessage(
                    requestID: 3,
                    handle: fileHandle
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeSFTPFixture(
    senderChannel: UInt32,
    extensions: [SSHSFTPExtension] = [],
    sftpMessagesAfterVersion: [SSHSFTPMessage]
) async throws -> (
    client: SSHTransportProtocolClient,
    transport: ProtocolClientMockSSHByteStreamTransport,
    activation: SSHCurve25519TransportActivation
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
                senderChannel: senderChannel,
                initialWindowSize: 512,
                maximumPacketSize: 128,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: extensions
            )
        )
    )
    let extraPayloads = try sftpMessagesAfterVersion.map(makeSFTPChannelDataPayload(_:))

    return try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
        ] + extraPayloads
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeSFTPChannelDataPayload(_ message: SSHSFTPMessage) throws -> [UInt8] {
    let packet = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(message)
    )
    return try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: packet
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeExtendedReplyMessage(
    requestID: UInt32,
    attributes: SSHSFTPFileSystemAttributes
) -> SSHSFTPMessage {
    var writer = SSHWireWriter()
    writer.write(uint64: attributes.blockSize)
    writer.write(uint64: attributes.fundamentalBlockSize)
    writer.write(uint64: attributes.totalBlocks)
    writer.write(uint64: attributes.freeBlocks)
    writer.write(uint64: attributes.availableBlocks)
    writer.write(uint64: attributes.totalFileNodes)
    writer.write(uint64: attributes.freeFileNodes)
    writer.write(uint64: attributes.availableFileNodes)
    writer.write(uint64: attributes.fileSystemID)
    writer.write(uint64: attributes.flags.rawValue)
    writer.write(uint64: attributes.maximumFilenameLength)
    return .extendedReply(
        SSHSFTPExtendedReplyMessage(
            requestID: requestID,
            data: writer.bytes
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func extractSentSFTPMessages(
    from fixture: (
        client: SSHTransportProtocolClient,
        transport: ProtocolClientMockSSHByteStreamTransport,
        activation: SSHCurve25519TransportActivation
    )
) async throws -> [SSHSFTPMessage] {
    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    return try packets.dropFirst(5).map(parseSFTPMessage(from:))
}
