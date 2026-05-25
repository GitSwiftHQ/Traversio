// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientExecutesCommandAfterPasswordAuthentication() async throws {
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
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("Linux traversio-test\n".utf8)
            )
        )
    )
    let stderrPayload = try SSHConnectionMessageSerializer().serialize(
        .channelExtendedData(
            SSHChannelExtendedDataMessage(
                recipientChannel: 0,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("warning\n".utf8)
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
            channelSuccessPayload,
            stdoutPayload,
            stderrPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    let authResult = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.execute(command: "uname -a")

    #expect(authResult.outcome == .success(SSHUserAuthenticationSuccessMessage()))
    #expect(result.channel.localChannelID == 0)
    #expect(result.channel.remoteChannelID == 42)
    #expect(result.standardOutput == Array("Linux traversio-test\n".utf8))
    #expect(result.standardError == Array("warning\n".utf8))
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)
    let latency = try #require(await fixture.client.currentLatency())
    #expect(latency.source == .channelRequest)
    #expect(latency.measuredAtUptimeNanoseconds > 0)
    #expect(latency.roundTripTimeMilliseconds >= 0)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let execPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

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
    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseExecCommand(from: execRequest) == "uname -a")
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 42)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientSendsEnvironmentRequestsBeforeExec() async throws {
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
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let firstEnvironmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let secondEnvironmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let execSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("en_US.UTF-8\n".utf8)
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
            firstEnvironmentSuccessPayload,
            secondEnvironmentSuccessPayload,
            execSuccessPayload,
            stdoutPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let environment = [
        SSHSessionEnvironmentVariable(name: "LANG", value: "en_US.UTF-8"),
        SSHSessionEnvironmentVariable(name: "LC_ALL", value: "en_US.UTF-8"),
    ]
    let result = try await fixture.client.execute(
        command: "printenv LANG",
        environment: environment
    )

    #expect(result.channel.remoteChannelID == 42)
    #expect(result.standardOutput == Array("en_US.UTF-8\n".utf8))
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
    let firstEnvironmentPacket = try #require(try parser.nextPacket())
    let secondEnvironmentPacket = try #require(try parser.nextPacket())
    let execPacket = try #require(try parser.nextPacket())
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

    let requestCoder = SSHSessionRequestCoder()
    let firstEnvironmentMessage = try SSHConnectionMessageParser().parse(
        firstEnvironmentPacket.payload
    )
    let firstEnvironmentRequest = try #require({
        if case let .channelRequest(value) = firstEnvironmentMessage {
            return value
        }
        return nil
    }())
    #expect(firstEnvironmentRequest.wantReply)
    #expect(
        try requestCoder.parseEnvironmentRequest(from: firstEnvironmentRequest)
            == environment[0]
    )

    let secondEnvironmentMessage = try SSHConnectionMessageParser().parse(
        secondEnvironmentPacket.payload
    )
    let secondEnvironmentRequest = try #require({
        if case let .channelRequest(value) = secondEnvironmentMessage {
            return value
        }
        return nil
    }())
    #expect(secondEnvironmentRequest.wantReply)
    #expect(
        try requestCoder.parseEnvironmentRequest(from: secondEnvironmentRequest)
            == environment[1]
    )

    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try requestCoder.parseExecCommand(from: execRequest) == "printenv LANG")
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 42)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesGlobalRequestWhileOpeningSessionChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let globalRequestPayload = try SSHConnectionMessageSerializer().serialize(
        .globalRequest(
            SSHGlobalRequestMessage(
                requestName: "keepalive@openssh.com",
                wantReply: true,
                requestData: []
            )
        )
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 77,
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            globalRequestPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.execute(command: "true")

    #expect(result.channel.remoteChannelID == 77)
    #expect(result.exitStatus == 0)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(
        bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5] + sentPayloads[6] +
            sentPayloads[7]
    )
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let authRequestPacket = try #require(try parser.nextPacket())
    let openPacket = try #require(try parser.nextPacket())
    let requestFailurePacket = try #require(try parser.nextPacket())
    let execPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

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
    #expect(
        try SSHConnectionMessageParser().parse(requestFailurePacket.payload)
            == .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseExecCommand(from: execRequest) == "true")
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 77)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReplenishesReceiveWindowDuringExecOutput() async throws {
    let firstChunk = Array(repeating: UInt8(0x61), count: 40)
    let secondChunk = Array(repeating: UInt8(0x62), count: 40)

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
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let firstOutputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: firstChunk
            )
        )
    )
    let secondOutputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: secondChunk
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
            channelSuccessPayload,
            firstOutputPayload,
            secondOutputPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let result = try await fixture.client.execute(
        command: "cat /tmp/test",
        localInitialWindowSize: 64,
        localMaximumPacketSize: 64
    )

    #expect(result.channel.remoteChannelID == 88)
    #expect(result.standardOutput == firstChunk + secondChunk)
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
    let execPacket = try #require(try parser.nextPacket())
    let firstWindowAdjustPacket = try #require(try parser.nextPacket())
    let secondWindowAdjustPacket = try #require(try parser.nextPacket())
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
                    initialWindowSize: 64,
                    maximumPacketSize: 64,
                    channelTypeData: []
                )
            )
    )
    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseExecCommand(from: execRequest) == "cat /tmp/test")
    #expect(
        try SSHConnectionMessageParser().parse(firstWindowAdjustPacket.payload)
            == .channelWindowAdjust(
                SSHChannelWindowAdjustMessage(recipientChannel: 88, bytesToAdd: 40)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(secondWindowAdjustPacket.payload)
            == .channelWindowAdjust(
                SSHChannelWindowAdjustMessage(recipientChannel: 88, bytesToAdd: 40)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 88)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRejectsChannelDataThatExceedsReceiveWindow() async throws {
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
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let oversizedOutputPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array(repeating: UInt8(0x78), count: 17)
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            oversizedOutputPayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    do {
        _ = try await fixture.client.execute(
            command: "cat /tmp/test",
            localInitialWindowSize: 16,
            localMaximumPacketSize: 32
        )
        Issue.record("Expected receive-window-exceeded error")
    } catch {
        #expect(
            error as? SSHConnectionError
                == .channelReceiveWindowExceeded(
                    channelID: 0,
                    received: 17,
                    remaining: 16
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStreamsExecInputAndSendsEOF() async throws {
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
                senderChannel: 73,
                initialWindowSize: 8,
                maximumPacketSize: 4,
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
    let fixture = try await makeActivatedTransportFixture(
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

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "cat")
    try await session.write(Array("abcdefgh".utf8))
    try await session.sendEOF()
    let transcript = try await session.collectOutputUntilClose()

    #expect(transcript.channel.remoteChannelID == 73)
    #expect(transcript.standardOutput.isEmpty)
    #expect(transcript.standardError.isEmpty)
    #expect(transcript.exitStatus == 0)
    #expect(transcript.didReceiveEOF)

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
    let execPacket = try #require(try parser.nextPacket())
    let firstInputPacket = try #require(try parser.nextPacket())
    let secondInputPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 10)
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
    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseExecCommand(from: execRequest) == "cat")
    #expect(
        try SSHConnectionMessageParser().parse(firstInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 73,
                    data: Array("abcd".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(secondInputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 73,
                    data: Array("efgh".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(
                SSHChannelEOFMessage(recipientChannel: 73)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 73)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStreamsExecStandardErrorInputAndSendsEOF() async throws {
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
                senderChannel: 75,
                initialWindowSize: 8,
                maximumPacketSize: 4,
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
    let fixture = try await makeActivatedTransportFixture(
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

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "cat >&2")
    try await session.writeStandardError(Array("abcdefgh".utf8))
    try await session.sendEOF()
    let transcript = try await session.collectOutputUntilClose()

    #expect(transcript.channel.remoteChannelID == 75)
    #expect(transcript.standardOutput.isEmpty)
    #expect(transcript.standardError.isEmpty)
    #expect(transcript.exitStatus == 0)
    #expect(transcript.didReceiveEOF)

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
    let firstInputPacket = try #require(try parser.nextPacket())
    let secondInputPacket = try #require(try parser.nextPacket())
    let eofPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 10)
    #expect(
        try SSHConnectionMessageParser().parse(firstInputPacket.payload)
            == .channelExtendedData(
                SSHChannelExtendedDataMessage(
                    recipientChannel: 75,
                    dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                    data: Array("abcd".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(secondInputPacket.payload)
            == .channelExtendedData(
                SSHChannelExtendedDataMessage(
                    recipientChannel: 75,
                    dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                    data: Array("efgh".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(eofPacket.payload)
            == .channelEOF(
                SSHChannelEOFMessage(recipientChannel: 75)
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 75)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRejectsUnsentExecInputWhenChannelCloses() async throws {
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
                senderChannel: 74,
                initialWindowSize: 4,
                maximumPacketSize: 4,
                channelTypeData: []
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
            channelSuccessPayload,
            closePayload,
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let session = try await fixture.client.openExecSession(command: "cat")

    do {
        try await session.write(Array("abcdefgh".utf8))
        Issue.record("Expected channel-closed-before-sending error")
    } catch {
        #expect(
            error as? SSHConnectionError
                == .channelClosedBeforeSending(channelID: 0, unsentByteCount: 4)
        )
    }

    let transcript = try await session.collectOutputUntilClose()
    #expect(transcript.channel.remoteChannelID == 74)
    #expect(transcript.standardOutput.isEmpty)
    #expect(transcript.standardError.isEmpty)
    #expect(transcript.exitStatus == nil)
    #expect(!transcript.didReceiveEOF)

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
    let execPacket = try #require(try parser.nextPacket())
    let inputPacket = try #require(try parser.nextPacket())
    let closePacket = try #require(try parser.nextPacket())

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
    let execMessage = try SSHConnectionMessageParser().parse(execPacket.payload)
    let execRequest = try #require({
        if case let .channelRequest(value) = execMessage {
            return value
        }
        return nil
    }())
    #expect(try SSHSessionRequestCoder().parseExecCommand(from: execRequest) == "cat")
    #expect(
        try SSHConnectionMessageParser().parse(inputPacket.payload)
            == .channelData(
                SSHChannelDataMessage(
                    recipientChannel: 74,
                    data: Array("abcd".utf8)
                )
            )
    )
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 74)
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadsExecEventsIncrementally() async throws {
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
                senderChannel: 61,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
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
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 17)
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
            channelSuccessPayload,
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
    let session = try await fixture.client.openExecSession(command: "printf test")

    #expect(try await session.readEvent() == .standardOutput(Array("hello stdout".utf8)))
    #expect(try await session.readEvent() == .standardError(Array("hello stderr".utf8)))
    #expect(try await session.readEvent() == .exitStatus(17))
    #expect(try await session.readEvent() == .endOfFile)
    #expect(try await session.readEvent() == nil)
    #expect(await fixture.client.managedSessionStates.isEmpty)
}

@Test
func transportProtocolClientRejectsExecBeforeAuthenticatedConnectionService() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    let client = SSHTransportProtocolClient(transport: transport)

    do {
        _ = try await client.execute(command: "uname -a")
        Issue.record("Expected authenticated-connection-required error")
    } catch {
        #expect(
            error as? SSHConnectionError == .authenticatedConnectionRequired
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesConcurrentExecSessionOpensOnOneConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 40,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let secondOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 41,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let secondChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let firstChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let secondStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: Array("second\n".utf8)
            )
        )
    )
    let firstStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("first\n".utf8)
            )
        )
    )
    let secondExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 1, exitStatus: 2)
    )
    let firstExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 1)
    )
    let secondEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let firstEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let secondClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let firstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstOpenConfirmationPayload,
            secondOpenConfirmationPayload,
            secondChannelSuccessPayload,
            firstChannelSuccessPayload,
            secondStdoutPayload,
            firstStdoutPayload,
            secondExitStatusPayload,
            firstExitStatusPayload,
            secondEOFPayload,
            firstEOFPayload,
            secondClosePayload,
            firstClosePayload,
        ],
        receiveDelayNanoseconds: 50_000_000,
        sendDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let firstTask = Task {
        try await fixture.client.openExecSession(command: "first-command")
    }
    defer {
        firstTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: 2_000,
            sleepNanoseconds: 1_000_000
        )
    )

    let secondTask = Task {
        try await fixture.client.openExecSession(command: "second-command")
    }
    defer {
        secondTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 2,
            maxAttempts: 2_000,
            sleepNanoseconds: 1_000_000
        )
    )

    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 4,
            maxAttempts: 2_000,
            sleepNanoseconds: 1_000_000
        )
    )

    let firstSession = try await firstTask.value
    let secondSession = try await secondTask.value

    async let firstTranscript = firstSession.collectOutputUntilClose()
    async let secondTranscript = secondSession.collectOutputUntilClose()

    let (firstResult, secondResult) = try await (firstTranscript, secondTranscript)

    #expect(firstResult.channel.localChannelID == 0)
    #expect(firstResult.channel.remoteChannelID == 40)
    #expect(firstResult.standardOutput == Array("first\n".utf8))
    #expect(firstResult.exitStatus == 1)
    #expect(firstResult.didReceiveEOF)

    #expect(secondResult.channel.localChannelID == 1)
    #expect(secondResult.channel.remoteChannelID == 41)
    #expect(secondResult.standardOutput == Array("second\n".utf8))
    #expect(secondResult.exitStatus == 2)
    #expect(secondResult.didReceiveEOF)

    #expect(await fixture.transport.maximumConcurrentReceiveCountObserved() == 1)
    #expect(await fixture.transport.maximumConcurrentSendCountObserved() == 1)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesFastCompletingConcurrentExecRequestsOnOneConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 60,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let secondOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 61,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let firstChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let firstStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("fast-first\n".utf8)
            )
        )
    )
    let firstExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 11)
    )
    let firstEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let firstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let secondChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let secondStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: Array("fast-second\n".utf8)
            )
        )
    )
    let secondExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 1, exitStatus: 12)
    )
    let secondEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let secondClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstOpenConfirmationPayload,
            secondOpenConfirmationPayload,
            firstChannelSuccessPayload,
            firstStdoutPayload,
            firstExitStatusPayload,
            firstEOFPayload,
            firstClosePayload,
            secondChannelSuccessPayload,
            secondStdoutPayload,
            secondExitStatusPayload,
            secondEOFPayload,
            secondClosePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let firstTask = Task {
        try await fixture.client.openExecSession(command: "fast-first-command")
    }
    defer {
        firstTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let secondTask = Task {
        try await fixture.client.openExecSession(command: "fast-second-command")
    }
    defer {
        secondTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 2
        )
    )
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 4
        )
    )

    let firstSession = try await firstTask.value
    let secondSession = try await secondTask.value

    async let firstTranscript = firstSession.collectOutputUntilClose()
    async let secondTranscript = secondSession.collectOutputUntilClose()

    let (firstResult, secondResult) = try await (firstTranscript, secondTranscript)

    #expect(firstResult.channel.remoteChannelID == 60)
    #expect(firstResult.standardOutput == Array("fast-first\n".utf8))
    #expect(firstResult.exitStatus == 11)
    #expect(firstResult.didReceiveEOF)

    #expect(secondResult.channel.remoteChannelID == 61)
    #expect(secondResult.standardOutput == Array("fast-second\n".utf8))
    #expect(secondResult.exitStatus == 12)
    #expect(secondResult.didReceiveEOF)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientQueuesPreManagedSessionMessagesBeforeExecRequestReply() async throws {
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
                senderChannel: 62,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let earlyStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("early-output\n".utf8)
            )
        )
    )
    let earlyExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 13)
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
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
            earlyStdoutPayload,
            earlyExitStatusPayload,
            channelSuccessPayload,
            eofPayload,
            closePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let session = try await fixture.client.openExecSession(command: "early-output-command")
    let transcript = try await session.collectOutputUntilClose()

    #expect(transcript.channel.localChannelID == 0)
    #expect(transcript.channel.remoteChannelID == 62)
    #expect(transcript.standardOutput == Array("early-output\n".utf8))
    #expect(transcript.exitStatus == 13)
    #expect(transcript.didReceiveEOF)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReturnsRekeyDeferredExecReplyToCurrentWaiter() async throws {
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("deferred-through-rekey\n".utf8)
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
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: false,
        channelOpenConfirmationSenderChannel: 64,
        encryptedPayloadsBeforeClientInitiatedRekeyResponse: [
            channelSuccessPayload,
            stdoutPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: 4,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: nil
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    _ = try await client.authenticatePassword(username: "root", password: "s3cr3t")

    let result = try await withOptionalTimeout(
        nanoseconds: 1_000_000_000,
        timeoutError: SSHTimeoutError.channelRequestReply(
            requestType: "exec",
            durationNanoseconds: 1_000_000_000
        )
    ) {
        try await client.execute(command: "printf deferred-through-rekey")
    }
    let rekeyMetrics = await client.rekeyMetricsSnapshot()

    #expect(result.channel.localChannelID == 0)
    #expect(result.channel.remoteChannelID == 64)
    #expect(result.standardOutput == Array("deferred-through-rekey\n".utf8))
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesSequentialConcurrentExecWavesOnOneConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 70,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let secondOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 71,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let firstChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let secondChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let firstStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("wave-one-first\n".utf8)
            )
        )
    )
    let secondStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: Array("wave-one-second\n".utf8)
            )
        )
    )
    let firstExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 21)
    )
    let secondExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 1, exitStatus: 22)
    )
    let firstEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let secondEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let firstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let secondClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let lateDuplicateFirstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let thirdOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 2,
                senderChannel: 72,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let fourthOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 3,
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let thirdChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 2))
    )
    let fourthChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 3))
    )
    let thirdStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 2,
                data: Array("wave-two-first\n".utf8)
            )
        )
    )
    let fourthStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 3,
                data: Array("wave-two-second\n".utf8)
            )
        )
    )
    let thirdExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 2, exitStatus: 23)
    )
    let fourthExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 3, exitStatus: 24)
    )
    let thirdEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 2))
    )
    let fourthEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 3))
    )
    let thirdClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 2))
    )
    let fourthClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 3))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstOpenConfirmationPayload,
            secondOpenConfirmationPayload,
            firstChannelSuccessPayload,
            secondChannelSuccessPayload,
            firstStdoutPayload,
            secondStdoutPayload,
            firstExitStatusPayload,
            secondExitStatusPayload,
            firstEOFPayload,
            secondEOFPayload,
            firstClosePayload,
            secondClosePayload,
            lateDuplicateFirstClosePayload,
            thirdOpenConfirmationPayload,
            fourthOpenConfirmationPayload,
            thirdChannelSuccessPayload,
            fourthChannelSuccessPayload,
            thirdStdoutPayload,
            fourthStdoutPayload,
            thirdExitStatusPayload,
            fourthExitStatusPayload,
            thirdEOFPayload,
            fourthEOFPayload,
            thirdClosePayload,
            fourthClosePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let firstWaveBaseline = await fixture.transport.sentPayloads().count
    let firstWaveFirstTask = Task {
        try await fixture.client.openExecSession(command: "wave-one-first-command")
    }
    defer {
        firstWaveFirstTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: firstWaveBaseline + 1,
            maxAttempts: 2_000
        )
    )

    let firstWaveSecondTask = Task {
        try await fixture.client.openExecSession(command: "wave-one-second-command")
    }
    defer {
        firstWaveSecondTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: firstWaveBaseline + 4,
            maxAttempts: 2_000
        )
    )

    let firstWaveFirstSession = try await firstWaveFirstTask.value
    let firstWaveSecondSession = try await firstWaveSecondTask.value
    async let firstWaveFirstTranscript = firstWaveFirstSession.collectOutputUntilClose()
    async let firstWaveSecondTranscript = firstWaveSecondSession.collectOutputUntilClose()

    let (firstWaveFirstResult, firstWaveSecondResult) = try await (
        firstWaveFirstTranscript,
        firstWaveSecondTranscript
    )

    #expect(firstWaveFirstResult.channel.remoteChannelID == 70)
    #expect(firstWaveFirstResult.standardOutput == Array("wave-one-first\n".utf8))
    #expect(firstWaveFirstResult.exitStatus == 21)
    #expect(firstWaveFirstResult.didReceiveEOF)

    #expect(firstWaveSecondResult.channel.remoteChannelID == 71)
    #expect(firstWaveSecondResult.standardOutput == Array("wave-one-second\n".utf8))
    #expect(firstWaveSecondResult.exitStatus == 22)
    #expect(firstWaveSecondResult.didReceiveEOF)

    let secondWaveBaseline = await fixture.transport.sentPayloads().count
    let secondWaveFirstTask = Task {
        try await fixture.client.openExecSession(command: "wave-two-first-command")
    }
    defer {
        secondWaveFirstTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: secondWaveBaseline + 1,
            maxAttempts: 2_000
        )
    )

    let secondWaveSecondTask = Task {
        try await fixture.client.openExecSession(command: "wave-two-second-command")
    }
    defer {
        secondWaveSecondTask.cancel()
    }
    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: secondWaveBaseline + 4,
            maxAttempts: 2_000
        )
    )

    let secondWaveFirstSession = try await secondWaveFirstTask.value
    let secondWaveSecondSession = try await secondWaveSecondTask.value
    async let secondWaveFirstTranscript = secondWaveFirstSession.collectOutputUntilClose()
    async let secondWaveSecondTranscript = secondWaveSecondSession.collectOutputUntilClose()

    let (secondWaveFirstResult, secondWaveSecondResult) = try await (
        secondWaveFirstTranscript,
        secondWaveSecondTranscript
    )

    #expect(secondWaveFirstResult.channel.localChannelID == 2)
    #expect(secondWaveFirstResult.channel.remoteChannelID == 72)
    #expect(secondWaveFirstResult.standardOutput == Array("wave-two-first\n".utf8))
    #expect(secondWaveFirstResult.exitStatus == 23)
    #expect(secondWaveFirstResult.didReceiveEOF)

    #expect(secondWaveSecondResult.channel.localChannelID == 3)
    #expect(secondWaveSecondResult.channel.remoteChannelID == 73)
    #expect(secondWaveSecondResult.standardOutput == Array("wave-two-second\n".utf8))
    #expect(secondWaveSecondResult.exitStatus == 24)
    #expect(secondWaveSecondResult.didReceiveEOF)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesFiveConcurrentExecCollectorsOnOneConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )

    var serverPayloads: [[UInt8]] = [serviceAcceptPayload, authSuccessPayload]
    for localChannelID in 0..<5 {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelOpenConfirmation(
                    SSHChannelOpenConfirmationMessage(
                        recipientChannel: UInt32(localChannelID),
                        senderChannel: UInt32(80 + localChannelID),
                        initialWindowSize: 1_048_576,
                        maximumPacketSize: 32_768,
                        channelTypeData: []
                    )
                )
            )
        )
    }
    for localChannelID in 0..<5 {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelSuccess(
                    SSHChannelSuccessMessage(recipientChannel: UInt32(localChannelID))
                )
            )
        )
    }
    for localChannelID in [4, 2, 0, 3, 1] {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelData(
                    SSHChannelDataMessage(
                        recipientChannel: UInt32(localChannelID),
                        data: Array("collector-\(localChannelID)\n".utf8)
                    )
                )
            )
        )
    }
    for localChannelID in [1, 3, 4, 0, 2] {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                SSHSessionRequestCoder().makeExitStatusRequest(
                    recipientChannel: UInt32(localChannelID),
                    exitStatus: UInt32(31 + localChannelID)
                )
            )
        )
    }
    for localChannelID in [2, 4, 1, 0, 3] {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelEOF(SSHChannelEOFMessage(recipientChannel: UInt32(localChannelID)))
            )
        )
    }
    for localChannelID in [3, 0, 4, 2, 1] {
        serverPayloads.append(
            try SSHConnectionMessageSerializer().serialize(
                .channelClose(SSHChannelCloseMessage(recipientChannel: UInt32(localChannelID)))
            )
        )
    }

    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: serverPayloads,
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let baselineSentCount = await fixture.transport.sentPayloads().count
    let tasks = (0..<5).map { index in
        Task {
            try await fixture.client.openExecSession(command: "collector-command-\(index)")
        }
    }
    defer {
        for task in tasks {
            task.cancel()
        }
    }

    #expect(
        await waitForSentPayloadCount(
            on: fixture.transport,
            minimumCount: baselineSentCount + 10,
            maxAttempts: 2_000
        )
    )

    var handles: [SSHSessionHandle] = []
    for task in tasks {
        handles.append(try await task.value)
    }

    var transcripts: [SSHSessionTranscript] = []
    for handle in handles {
        transcripts.append(try await handle.collectOutputUntilClose())
    }
    transcripts.sort { $0.channel.localChannelID < $1.channel.localChannelID }

    #expect(transcripts.count == 5)
    for (index, transcript) in transcripts.enumerated() {
        #expect(transcript.channel.localChannelID == UInt32(index))
        #expect(transcript.channel.remoteChannelID == UInt32(80 + index))
        #expect(transcript.standardOutput == Array("collector-\(index)\n".utf8))
        #expect(transcript.exitStatus == UInt32(31 + index))
        #expect(transcript.didReceiveEOF)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientIgnoresLateControlMessageForCompletedConcurrentExecChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 50,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let secondOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 51,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let firstChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let secondChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let firstStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("first-late\n".utf8)
            )
        )
    )
    let firstExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 7)
    )
    let firstEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let firstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let lateDuplicateFirstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let secondStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: Array("second-late\n".utf8)
            )
        )
    )
    let secondExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 1, exitStatus: 8)
    )
    let secondEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let secondClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstOpenConfirmationPayload,
            secondOpenConfirmationPayload,
            firstChannelSuccessPayload,
            secondChannelSuccessPayload,
            firstStdoutPayload,
            firstExitStatusPayload,
            firstEOFPayload,
            firstClosePayload,
            lateDuplicateFirstClosePayload,
            secondStdoutPayload,
            secondExitStatusPayload,
            secondEOFPayload,
            secondClosePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    async let firstSession = fixture.client.openExecSession(command: "first-late-command")
    async let secondSession = fixture.client.openExecSession(command: "second-late-command")

    let (firstHandle, secondHandle) = try await (firstSession, secondSession)
    async let firstTranscript = firstHandle.collectOutputUntilClose()
    async let secondTranscript = secondHandle.collectOutputUntilClose()

    let (firstResult, secondResult) = try await (firstTranscript, secondTranscript)
    let transcriptsByRemoteChannelID = Dictionary(
        uniqueKeysWithValues: [firstResult, secondResult].map { ($0.channel.remoteChannelID, $0) }
    )

    let firstChannelResult = try #require(transcriptsByRemoteChannelID[50])
    #expect(firstChannelResult.standardOutput == Array("first-late\n".utf8))
    #expect(firstChannelResult.exitStatus == 7)
    #expect(firstChannelResult.didReceiveEOF)

    let secondChannelResult = try #require(transcriptsByRemoteChannelID[51])
    #expect(secondChannelResult.standardOutput == Array("second-late\n".utf8))
    #expect(secondChannelResult.exitStatus == 8)
    #expect(secondChannelResult.didReceiveEOF)
}
