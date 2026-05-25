// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCapturesShellStartupAfterPasswordAuthentication() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 8_192
            )
        )
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let welcomePayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("Ubuntu 22.04.5 LTS\r\nLast login: now\r\nroot@test:~# ".utf8)
            )
        )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            windowAdjustPayload,
            shellSuccessPayload,
            welcomePayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.captureShellStartup()

    #expect(result.channel.localChannelID == 0)
    #expect(result.channel.remoteChannelID == 64)
    #expect(result.standardOutput == Array("Ubuntu 22.04.5 LTS\r\nLast login: now\r\nroot@test:~# ".utf8))
    #expect(result.standardError.isEmpty)
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6] +
            sentPayloads[7] + sentPayloads[8]
    )
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
    let inputPacket = try #require(try parser.nextPacket())
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
    let ptyMessage = try SSHConnectionMessageParser().parse(ptyPacket.payload)
    let ptyRequest = try #require({
        if case let .channelRequest(value) = ptyMessage {
            return value
        }
        return nil
    }())
    #expect(
        try SSHSessionRequestCoder().parsePseudoTerminalRequest(from: ptyRequest)
            == .default
    )
    let shellMessage = try SSHConnectionMessageParser().parse(shellPacket.payload)
    let shellRequest = try #require({
        if case let .channelRequest(value) = shellMessage {
            return value
        }
        return nil
    }())
    try SSHSessionRequestCoder().parseShellRequest(from: shellRequest)
    #expect(
        try SSHConnectionMessageParser().parse(inputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("exit\n".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 64)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSendsEnvironmentRequestsBeforePseudoTerminalAndShell() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            environmentSuccessPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession(
        environment: [
            SSHSessionEnvironmentVariable(name: "LANG", value: "en_US.UTF-8")
        ]
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
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
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

    let environmentMessage = try SSHConnectionMessageParser().parse(environmentPacket.payload)
    let environmentRequest = try #require({
        if case let .channelRequest(value) = environmentMessage {
            return value
        }
        return nil
    }())
    #expect(environmentRequest.wantReply)
    #expect(
        try SSHSessionRequestCoder().parseEnvironmentRequest(from: environmentRequest)
            == SSHSessionEnvironmentVariable(name: "LANG", value: "en_US.UTF-8")
    )

    let ptyMessage = try SSHConnectionMessageParser().parse(ptyPacket.payload)
    let ptyRequest = try #require({
        if case let .channelRequest(value) = ptyMessage {
            return value
        }
        return nil
    }())
    #expect(
        try SSHSessionRequestCoder().parsePseudoTerminalRequest(from: ptyRequest)
            == .default
    )

    let shellMessage = try SSHConnectionMessageParser().parse(shellPacket.payload)
    let shellRequest = try #require({
        if case let .channelRequest(value) = shellMessage {
            return value
        }
        return nil
    }())
    try SSHSessionRequestCoder().parseShellRequest(from: shellRequest)
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 64)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientPreservesWindowAdjustmentsReceivedBeforeShellReply() async throws {
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
                initialWindowSize: 0,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 5
            )
        )
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            windowAdjustPayload,
            shellSuccessPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.captureShellStartup(
        initialInput: Array("exit\n".utf8)
    )

    #expect(result.channel.remoteChannelID == 64)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError.isEmpty)
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)

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
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
    let inputPacket = try #require(try parser.nextPacket())
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
    #expect(try SSHConnectionMessageParser().parse(ptyPacket.payload).messageID == .channelRequest)
    #expect(try SSHConnectionMessageParser().parse(shellPacket.payload).messageID == .channelRequest)
    #expect(
        try SSHConnectionMessageParser().parse(inputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("exit\n".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 64)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReportsAndAdjustsChannelWindows() async throws {
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
                initialWindowSize: 32,
                maximumPacketSize: 8,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let remoteWindowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 4
            )
        )
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let outputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("abcd".utf8)
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            remoteWindowAdjustPayload,
            shellSuccessPayload,
            outputPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession(
        localInitialWindowSize: 16,
        localMaximumPacketSize: 8
    )

    let initialSnapshot = try await session.channelWindowSnapshot()
    #expect(
        initialSnapshot == SSHChannelWindowSnapshot(
            localChannelID: 0,
            remoteChannelID: 64,
            receiveWindowByteCount: 16,
            receiveInitialWindowByteCount: 16,
            sendWindowByteCount: 36,
            sendInitialWindowByteCount: 32,
            sendMaximumPacketByteCount: 8
        )
    )

    #expect(try await session.readEvent() == .standardOutput(Array("abcd".utf8)))
    let afterReadSnapshot = try await session.channelWindowSnapshot()
    #expect(afterReadSnapshot.receiveWindowByteCount == 12)
    #expect(afterReadSnapshot.sendWindowByteCount == 36)

    let afterAdjustSnapshot = try await session.adjustReceiveWindow(by: 5)
    #expect(afterAdjustSnapshot.receiveWindowByteCount == 17)
    #expect(afterAdjustSnapshot.sendWindowByteCount == 36)
    #expect(try await session.adjustReceiveWindow(by: 0) == afterAdjustSnapshot)

    do {
        _ = try await session.adjustReceiveWindow(by: UInt32.max)
        Issue.record("Expected receive-window overflow")
    } catch {
        #expect(
            error as? SSHConnectionError
                == .channelReceiveWindowOverflow(
                    channelID: 0,
                    current: 17,
                    adjustment: UInt32.max
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

    var windowAdjusts: [SSHChannelWindowAdjustMessage] = []
    while let packet = try parser.nextPacket() {
        if case let .channelWindowAdjust(windowAdjust) =
            try? SSHConnectionMessageParser().parse(packet.payload) {
            windowAdjusts.append(windowAdjust)
        }
    }

    #expect(
        windowAdjusts == [
            SSHChannelWindowAdjustMessage(
                recipientChannel: 64,
                bytesToAdd: 5
            )
        ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientChunksShellInputUsingRemoteWindowAdjustments() async throws {
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
                initialWindowSize: 5,
                maximumPacketSize: 4,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let windowAdjustPayload = try SSHConnectionMessageSerializer().serialize(
        .channelWindowAdjust(
            SSHChannelWindowAdjustMessage(
                recipientChannel: 0,
                bytesToAdd: 5
            )
        )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
            windowAdjustPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.captureShellStartup(
        initialInput: Array("abcdefghij".utf8)
    )

    #expect(result.channel.remoteChannelID == 64)
    #expect(result.standardOutput.isEmpty)
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)

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
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
    let firstInputPacket = try #require(try parser.nextPacket())
    let secondInputPacket = try #require(try parser.nextPacket())
    let thirdInputPacket = try #require(try parser.nextPacket())
    let fourthInputPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 12)
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
    #expect(try SSHConnectionMessageParser().parse(ptyPacket.payload).messageID == .channelRequest)
    #expect(try SSHConnectionMessageParser().parse(shellPacket.payload).messageID == .channelRequest)
    #expect(
        try SSHConnectionMessageParser().parse(firstInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("abcd".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(secondInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("e".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(thirdInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("fghi".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(fourthInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 64,
                    data: Array("j".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 64)
            )
    )
}

@Test
func transportProtocolClientRejectsShellCaptureBeforeAuthenticatedConnectionService() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    let client = SSHTransportProtocolClient(transport: transport)

    do {
        _ = try await client.captureShellStartup()
        Issue.record("Expected authenticated-connection-required error")
    } catch {
        #expect(
            error as? SSHConnectionError == .authenticatedConnectionRequired
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadsShellEventsIncrementally() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("hello stdout".utf8)
            )
        )
    )
    let stderrPayload = try SSHConnectionMessageSerializer().serialize(
        .channelExtendedData(
            SSHChannelExtendedDataMessage(
                recipientChannel: 0,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("hello stderr".utf8)
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 23)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
            stdoutPayload,
            stderrPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()

    #expect(try await session.readEvent() == .standardOutput(Array("hello stdout".utf8)))
    #expect(try await session.readEvent() == .standardError(Array("hello stderr".utf8)))
    #expect(try await session.readEvent() == .exitStatus(23))
    #expect(try await session.readEvent() == .endOfFile)
    #expect(try await session.readEvent() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSurfacesRemoteExitSignalAsEventAndTranscriptState() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let exitSignal = SSHSessionExitSignal(
        signal: .terminate,
        didCoreDump: false,
        errorMessage: "terminated by test",
        languageTag: "en-US"
    )
    let exitSignalPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitSignalRequest(
            recipientChannel: 0,
            exitSignal: exitSignal
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
            exitSignalPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()

    #expect(try await session.readEvent() == .exitSignal(exitSignal))
    #expect(try await session.readEvent() == .endOfFile)
    #expect(try await session.readEvent() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientResizesPseudoTerminalWithoutWaitingForReply() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()
    try await session.resizePseudoTerminal(
        characterWidth: 132,
        characterHeight: 43,
        pixelWidth: 1440,
        pixelHeight: 900
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
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
    let resizePacket = try #require(try parser.nextPacket())

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
    #expect(try SSHConnectionMessageParser().parse(ptyPacket.payload).messageID == .channelRequest)
    #expect(try SSHConnectionMessageParser().parse(shellPacket.payload).messageID == .channelRequest)

    let resizeMessage = try SSHConnectionMessageParser().parse(resizePacket.payload)
    let resizeRequest = try #require({
        if case let .channelRequest(value) = resizeMessage {
            return value
        }
        return nil
    }())
    #expect(!resizeRequest.wantReply)
    #expect(
        try SSHSessionRequestCoder().parseWindowChangeRequest(from: resizeRequest)
            == SSHPseudoTerminalWindowChange(
                characterWidth: 132,
                characterHeight: 43,
                pixelWidth: 1440,
                pixelHeight: 900
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCompletesPseudoTerminalResizeWhenCallerCancelsDuringTransportSend()
    async throws
{
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ],
        sendDelayNanoseconds: 100_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()

    let resizeTask = Task {
        try await session.resizePseudoTerminal(
            characterWidth: 160,
            characterHeight: 48,
            pixelWidth: 1920,
            pixelHeight: 1080
        )
    }
    try await Task.sleep(nanoseconds: 10_000_000)
    resizeTask.cancel()
    try await resizeTask.value

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2...].flatMap { $0 })
    var parsedConnectionMessages: [SSHConnectionMessage] = []
    while let packet = try parser.nextPacket() {
        if let connectionMessage = try? SSHConnectionMessageParser().parse(packet.payload) {
            parsedConnectionMessages.append(connectionMessage)
        }
    }

    let resizeRequest = try #require(parsedConnectionMessages.compactMap { message in
        if case let .channelRequest(request) = message,
           request.requestType == "window-change" {
            return request
        }
        return nil
    }.last)
    #expect(!resizeRequest.wantReply)
    #expect(
        try SSHSessionRequestCoder().parseWindowChangeRequest(from: resizeRequest)
            == SSHPseudoTerminalWindowChange(
                characterWidth: 160,
                characterHeight: 48,
                pixelWidth: 1920,
                pixelHeight: 1080
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSendsSignalWithoutWaitingForReply() async throws {
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
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openShellSession()
    try await session.sendSignal(.interrupt)

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
    let ptyPacket = try #require(try parser.nextPacket())
    let shellPacket = try #require(try parser.nextPacket())
    let signalPacket = try #require(try parser.nextPacket())

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
    #expect(try SSHConnectionMessageParser().parse(ptyPacket.payload).messageID == .channelRequest)
    #expect(try SSHConnectionMessageParser().parse(shellPacket.payload).messageID == .channelRequest)

    let signalMessage = try SSHConnectionMessageParser().parse(signalPacket.payload)
    let signalRequest = try #require({
        if case let .channelRequest(value) = signalMessage {
            return value
        }
        return nil
    }())
    #expect(!signalRequest.wantReply)
    #expect(try SSHSessionRequestCoder().parseSignalRequest(from: signalRequest) == .interrupt)
}
