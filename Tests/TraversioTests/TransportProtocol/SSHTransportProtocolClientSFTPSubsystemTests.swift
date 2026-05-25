// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientOpensSFTPSubsystemSessionAndUsesManagedWriteFlowControl() async throws {
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
                senderChannel: 81,
                initialWindowSize: 0,
                maximumPacketSize: 4,
                channelTypeData: []
            )
        )
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 5
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            windowAdjustPayload,
            channelSuccessPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openSFTPSubsystemSession()
    try await session.write(Array("abcde".utf8))
    try await session.close()

    #expect(await fixture.client.managedSessionStates.isEmpty)

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
    let subsystemPacket = try #require(try parser.nextPacket())
    let firstInputPacket = try #require(try parser.nextPacket())
    let secondInputPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 9)
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
    let subsystemMessage = try SSHConnectionMessageParser().parse(subsystemPacket.payload)
    let subsystemRequest = try #require({
        if case let .channelRequest(value) = subsystemMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseSubsystemRequest(from: subsystemRequest) == "sftp")
    #expect(
        try SSHConnectionMessageParser().parse(firstInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 81,
                    data: Array("abcd".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(secondInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 81,
                    data: Array("e".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 81)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientOpensSFTPClientAndCompletesVersionExchange() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let extensionInfoPayload = try SSHTransportMessageSerializer().serialize(
        .extensionInfo(
            SSHExtensionInfoMessage(
                entries: [
                    SSHExtensionInfoEntry(
                        name: "server-sig-algs",
                        value: Array("ssh-ed25519,rsa-sha2-512".utf8)
                    )
                ]
            )
        )
    )
    let debugPayload = try SSHTransportMessageSerializer().serialize(
        .debug(
            SSHDebugMessage(
                alwaysDisplay: false,
                message: "server debug",
                languageTag: "en-US"
            )
        )
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 0,
                maximumPacketSize: 32,
                channelTypeData: []
            )
        )
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 9
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
    let firstVersionChunkPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array(versionPacket.prefix(5))
            )
        )
    )
    let secondVersionChunkPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array(versionPacket.dropFirst(5))
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            extensionInfoPayload,
            debugPayload,
            openConfirmationPayload,
            windowAdjustPayload,
            channelSuccessPayload,
            firstVersionChunkPayload,
            secondVersionChunkPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    let versionExchange = try await sftpClient.currentVersionExchange()

    #expect(versionExchange.clientVersion == 3)
    #expect(versionExchange.serverVersion == 3)
    #expect(
        versionExchange.extensions == [
            SSHSFTPExtension(
                name: "posix-rename@openssh.com",
                data: Array("1".utf8)
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
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let subsystemPacket = try #require(try parser.nextPacket())
    let initPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 7)
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
    let subsystemMessage = try SSHConnectionMessageParser().parse(subsystemPacket.payload)
    let subsystemRequest = try #require({
        if case let .channelRequest(value) = subsystemMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseSubsystemRequest(from: subsystemRequest) == "sftp")

    let initMessage = try SSHConnectionMessageParser().parse(initPacket.payload)
    let initChannelData = try #require({
        if case let .channelData(value) = initMessage {
            return value
        }
        return nil
    }())
    let initPayload = try #require({
        var packetParser = SSHSFTPPacketParser()
        packetParser.append(bytes: initChannelData.data)
        return try packetParser.nextPayload()
    }())
    #expect(
        try SSHSFTPMessageParser().parse(initPayload)
            == .initialize(SSHSFTPInitializeMessage(version: 3))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSerializesConcurrentSFTPRequestWrites() async throws {
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
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(SSHSFTPVersionMessage(version: 3, extensions: []))
        )
    )
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag,
        size: 4096,
        userID: nil,
        groupID: nil,
        permissions: nil,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let firstAttributesPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: 0,
                    attributes: attributes
                )
            )
        )
    )
    let secondAttributesPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: 1,
                    attributes: attributes
                )
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            try SSHConnectionMessageSerializer().serialize(
                .channelData(
                    SSHChannelDataMessage(
                        recipientChannel: 0,
                        data: versionPacket
                    )
                )
            ),
            try SSHConnectionMessageSerializer().serialize(
                .channelData(
                    SSHChannelDataMessage(
                        recipientChannel: 0,
                        data: firstAttributesPacket
                    )
                )
            ),
            try SSHConnectionMessageSerializer().serialize(
                .channelData(
                    SSHChannelDataMessage(
                        recipientChannel: 0,
                        data: secondAttributesPacket
                    )
                )
            ),
        ],
        sendDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    async let first = sftpClient.lstat("/tmp/first")
    async let second = sftpClient.lstat("/tmp/second")
    let (firstAttributes, secondAttributes) = try await (first, second)

    #expect(firstAttributes == attributes)
    #expect(secondAttributes == attributes)

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
    let firstLStatPacket = try #require(try parser.nextPacket())
    let secondLStatPacket = try #require(try parser.nextPacket())

    let lstatMessages = try [
        parseSFTPMessage(from: firstLStatPacket),
        parseSFTPMessage(from: secondLStatPacket),
    ]
    let lstatPaths = try lstatMessages.map { message in
        let request = try #require({
            if case let .lstat(request) = message {
                return request
            }
            return nil
        }())
        return request.path
    }
    #expect(Set(lstatPaths) == ["/tmp/first", "/tmp/second"])
}

@Test
func transportProtocolClientRejectsSFTPSubsystemOpenBeforeAuthenticatedConnectionService() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    let client = SSHTransportProtocolClient(transport: transport)

    do {
        _ = try await client.openSFTPSubsystemSession()
        Issue.record("Expected authenticated-connection-required error")
    } catch {
        #expect(
            error as? SSHConnectionError == .authenticatedConnectionRequired
        )
    }
}

@Test
func transportProtocolClientRejectsSFTPClientOpenBeforeAuthenticatedConnectionService() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    let client = SSHTransportProtocolClient(transport: transport)

    do {
        _ = try await client.openSFTPClient()
        Issue.record("Expected authenticated-connection-required error")
    } catch {
        #expect(
            error as? SSHConnectionError == .authenticatedConnectionRequired
        )
    }
}
