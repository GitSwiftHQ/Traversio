// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientMakeDirectorySendsMakeDirectoryRequest() async throws {
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
                senderChannel: 95,
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
    let makeDirectoryStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let makeDirectoryStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: makeDirectoryStatusPacket
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
            makeDirectoryStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.makeDirectory(
        "/root/newdir",
        attributes: SSHSFTPFileAttributes(
            flags: SSHSFTPFileAttributes.permissionsFlag,
            size: nil,
            userID: nil,
            groupID: nil,
            permissions: 0o755,
            accessTime: nil,
            modificationTime: nil,
            extensions: []
        )
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
    let makeDirectoryPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: makeDirectoryPacket)
            == .makeDirectory(
                SSHSFTPMakeDirectoryMessage(
                    requestID: 0,
                    path: "/root/newdir",
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.permissionsFlag,
                        size: nil,
                        userID: nil,
                        groupID: nil,
                        permissions: 0o755,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRemoveFileSurfacesStatusFailure() async throws {
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
                senderChannel: 96,
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
    let removeStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
                    statusCode: .noSuchFile,
                    errorMessage: "No such file",
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
    let removeStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: removeStatusPacket
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
            removeStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        try await sftpClient.removeFile("/root/missing.txt")
        Issue.record("Expected SFTP status error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .status(
                    SSHSFTPStatusMessage(
                        requestID: 0,
                        statusCode: .noSuchFile,
                        errorMessage: "No such file",
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
    let removePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: removePacket)
            == .removeFile(
                SSHSFTPRemoveFileMessage(
                    requestID: 0,
                    path: "/root/missing.txt"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRemoveDirectorySendsRemoveDirectoryRequest() async throws {
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
                senderChannel: 97,
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
    let removeDirectoryStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let removeDirectoryStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: removeDirectoryStatusPacket
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
            removeDirectoryStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.removeDirectory("/root/empty-dir")

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
    let removeDirectoryPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: removeDirectoryPacket)
            == .removeDirectory(
                SSHSFTPRemoveDirectoryMessage(
                    requestID: 0,
                    path: "/root/empty-dir"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRenameSendsRenameRequest() async throws {
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
                senderChannel: 97,
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
    let renameStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let renameStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: renameStatusPacket
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
            renameStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.rename(
        "/root/old-name.txt",
        to: "/root/new-name.txt"
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
    let renamePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: renamePacket)
            == .rename(
                SSHSFTPRenameMessage(
                    requestID: 0,
                    oldPath: "/root/old-name.txt",
                    newPath: "/root/new-name.txt"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRenameUsesPosixRenameExtensionWhenAdvertised() async throws {
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
                senderChannel: 98,
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
                    extensions: [
                        SSHSFTPExtension(
                            name: "posix-rename@openssh.com",
                            data: Array("1".utf8)
                        )
                    ]
                )
            )
        )
    )
    let renameStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let renameStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: renameStatusPacket
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
            renameStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.rename(
        "/root/old-name.txt",
        to: "/root/new-name.txt"
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
    let renamePacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: renamePacket)
            == .posixRename(
                SSHSFTPPosixRenameMessage(
                    requestID: 0,
                    oldPath: "/root/old-name.txt",
                    newPath: "/root/new-name.txt"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCreateSymbolicLinkSendsSymbolicLinkRequest() async throws {
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
                senderChannel: 98,
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
    let symbolicLinkStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let symbolicLinkStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: symbolicLinkStatusPacket
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
            symbolicLinkStatusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.createSymbolicLink(
        targetPath: "/root/releases/current",
        linkPath: "/root/current"
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
    let symbolicLinkPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: symbolicLinkPacket)
            == .symbolicLink(
                SSHSFTPSymbolicLinkMessage(
                    requestID: 0,
                    targetPath: "/root/releases/current",
                    linkPath: "/root/current"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCreateSymbolicLinkUsesStandardWireOrderForAsyncSSH() async throws {
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
                senderChannel: 95,
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
    let symbolicLinkStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let symbolicLinkStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: symbolicLinkStatusPacket
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
            symbolicLinkStatusPayload,
        ],
        remoteIdentificationRawValue: "SSH-2.0-AsyncSSH_2.22.0"
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.createSymbolicLink(
        targetPath: "/root/releases/current",
        linkPath: "/root/current"
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
    let symbolicLinkPacket = try #require(try parser.nextPacket())
    let channelData = try #require({
        let message = try SSHConnectionMessageParser().parse(symbolicLinkPacket.payload)
        if case let .channelData(value) = message {
            return value
        }
        return nil
    }())
    let payload = try #require({
        var packetParser = SSHSFTPPacketParser()
        packetParser.append(bytes: channelData.data)
        return try packetParser.nextPayload()
    }())
    var reader = SSHWireReader(bytes: payload)

    #expect(try reader.readByte() == SSHSFTPMessageID.symbolicLink.rawValue)
    #expect(try reader.readUInt32() == 0)
    #expect(try reader.readUTF8String() == "/root/current")
    #expect(try reader.readUTF8String() == "/root/releases/current")
    #expect(reader.isAtEnd)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCreateSymbolicLinkUsesOpenSSHCompatibleWireOrderForDropbear() async throws {
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
                senderChannel: 96,
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
    let symbolicLinkStatusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
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
    let symbolicLinkStatusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: symbolicLinkStatusPacket
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
            symbolicLinkStatusPayload,
        ],
        remoteIdentificationRawValue: "SSH-2.0-dropbear_2024.85"
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    try await sftpClient.createSymbolicLink(
        targetPath: "/root/releases/current",
        linkPath: "/root/current"
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
    let symbolicLinkPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: symbolicLinkPacket)
            == .symbolicLink(
                SSHSFTPSymbolicLinkMessage(
                    requestID: 0,
                    targetPath: "/root/releases/current",
                    linkPath: "/root/current"
                )
            )
    )
}
