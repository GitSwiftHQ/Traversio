// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRealPathReturnsSingleNameEntry() async throws {
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
                senderChannel: 83,
                initialWindowSize: 0,
                maximumPacketSize: 64,
                channelTypeData: []
            )
        )
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 64
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
    let namePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .name(
                SSHSFTPNameMessage(
                    requestID: 0,
                    entries: [
                        SSHSFTPNameEntry(
                            filename: "/root",
                            longName: "/root",
                            attributes: .empty
                        )
                    ]
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
    let namePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: namePacket
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            windowAdjustPayload,
            channelSuccessPayload,
            versionPayload,
            namePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let entry = try await sftpClient.realPath(".")

    #expect(entry.filename == "/root")
    #expect(entry.longName == "/root")
    #expect(entry.attributes == .empty)

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
    let realPathPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: realPathPacket)
            == .realPath(
                SSHSFTPRealPathMessage(
                    requestID: 0,
                    path: "."
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRealPathSurfacesStatusFailure() async throws {
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
                senderChannel: 84,
                initialWindowSize: 32,
                maximumPacketSize: 64,
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
    let statusPacket = try SSHSFTPPacketSerializer().serialize(
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
            statusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        _ = try await sftpClient.realPath("/missing")
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
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadLinkReturnsSingleNameEntry() async throws {
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
                initialWindowSize: 64,
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
    let namePacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .name(
                SSHSFTPNameMessage(
                    requestID: 0,
                    entries: [
                        SSHSFTPNameEntry(
                            filename: "/root/releases/current",
                            longName: "/root/releases/current",
                            attributes: .empty
                        )
                    ]
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
    let namePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: namePacket
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
            namePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let entry = try await sftpClient.readLink("/root/current")

    #expect(entry.filename == "/root/releases/current")
    #expect(entry.longName == "/root/releases/current")
    #expect(entry.attributes == .empty)

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
    let readLinkPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: readLinkPacket)
            == .readLink(
                SSHSFTPReadLinkMessage(
                    requestID: 0,
                    path: "/root/current"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientLStatReturnsAttributes() async throws {
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
                senderChannel: 85,
                initialWindowSize: 32,
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
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.permissionsFlag |
            SSHSFTPFileAttributes.accessAndModificationTimeFlag,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: 0o777,
        accessTime: 1_700_000_010,
        modificationTime: 1_700_000_020,
        extensions: []
    )
    let attributesPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: 0,
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
            attributesPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let receivedAttributes = try await sftpClient.lstat("/root/link")

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
    let lstatPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: lstatPacket)
            == .lstat(
                SSHSFTPLStatMessage(
                    requestID: 0,
                    path: "/root/link"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientLStatSurfacesStatusFailure() async throws {
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
                senderChannel: 86,
                initialWindowSize: 64,
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
    let statusPacket = try SSHSFTPPacketSerializer().serialize(
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
            statusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        _ = try await sftpClient.lstat("/missing-link")
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
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStatReturnsAttributes() async throws {
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
                senderChannel: 85,
                initialWindowSize: 32,
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
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag |
            SSHSFTPFileAttributes.permissionsFlag |
            SSHSFTPFileAttributes.accessAndModificationTimeFlag,
        size: 4_096,
        userID: nil,
        groupID: nil,
        permissions: 0o755,
        accessTime: 1_700_000_000,
        modificationTime: 1_700_000_100,
        extensions: []
    )
    let attributesPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: 0,
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
            attributesPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let receivedAttributes = try await sftpClient.stat("/root")

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
    let statPacket = try #require(try parser.nextPacket())

    #expect(
        try parseSFTPMessage(from: statPacket)
            == .stat(
                SSHSFTPStatMessage(
                    requestID: 0,
                    path: "/root"
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStatSurfacesStatusFailure() async throws {
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
                senderChannel: 86,
                initialWindowSize: 32,
                maximumPacketSize: 64,
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
    let statusPacket = try SSHSFTPPacketSerializer().serialize(
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
            statusPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    do {
        _ = try await sftpClient.stat("/missing")
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
}
