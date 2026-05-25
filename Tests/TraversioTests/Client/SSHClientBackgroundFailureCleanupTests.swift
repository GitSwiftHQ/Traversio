// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshClientInvalidatesOpenSessionAfterBackgroundKeepaliveFailure() async throws {
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
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = try makeAuthenticatedBackgroundFailureTransport(
        additionalServerPayloadsAfterAuth: [
            openConfirmationPayload,
            channelSuccessPayload,
        ]
    )
    let connection = try await makeKeepaliveConnection(transport: transport)
    let session = try await connection.openExec("sleep 30")
    let baselineSentCount = await transport.sentPayloads().count

    try await waitForBackgroundFailure(on: transport, baselineSentCount: baselineSentCount)

    let failedSentCount = await transport.sentPayloads().count
    do {
        try await session.write("after-failure")
        Issue.record("Expected open session writes to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
    #expect(await transport.sentPayloads().count == failedSentCount)

    await connection.close()
}

@Test
func sshClientInvalidatesDirectTCPIPChannelAfterBackgroundKeepaliveFailure() async throws {
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 56,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let transport = try makeAuthenticatedBackgroundFailureTransport(
        additionalServerPayloadsAfterAuth: [
            openConfirmationPayload,
        ]
    )
    let connection = try await makeKeepaliveConnection(transport: transport)
    let channel = try await connection.openDirectTCPIPChannel(
        targetHost: "db.internal",
        targetPort: 5432,
        originatorAddress: "127.0.0.1",
        originatorPort: 61001
    )
    let baselineSentCount = await transport.sentPayloads().count

    try await waitForBackgroundFailure(on: transport, baselineSentCount: baselineSentCount)

    let failedSentCount = await transport.sentPayloads().count
    do {
        try await channel.write("after-failure")
        Issue.record("Expected direct-tcpip channel writes to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
    #expect(await transport.sentPayloads().count == failedSentCount)

    await connection.close()
}

@Test
func sshClientInvalidatesSFTPClientAfterBackgroundKeepaliveFailure() async throws {
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPVersionChannelDataPayload(recipientChannel: 0)
    let transport = try makeAuthenticatedBackgroundFailureTransport(
        additionalServerPayloadsAfterAuth: [
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
        ]
    )
    let connection = try await makeKeepaliveConnection(transport: transport)
    let sftp = try await connection.openSFTP()
    let baselineSentCount = await transport.sentPayloads().count

    try await waitForBackgroundFailure(on: transport, baselineSentCount: baselineSentCount)

    let failedSentCount = await transport.sentPayloads().count
    do {
        _ = try await sftp.stat("/tmp/test")
        Issue.record("Expected SFTP operations to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
    #expect(await transport.sentPayloads().count == failedSentCount)

    await connection.close()
}

private func makeAuthenticatedBackgroundFailureTransport(
    additionalServerPayloadsAfterAuth: [[UInt8]]
) throws -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ] + additionalServerPayloadsAfterAuth
    )
}

private func makeSFTPVersionChannelDataPayload(recipientChannel: UInt32) throws -> [UInt8] {
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
    return try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: recipientChannel,
                data: versionPacket
            )
        )
    )
}

private func makeKeepaliveConnection(
    transport: ConnectionFixtureMockSSHByteStreamTransport
) async throws -> SSHConnection {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval)
    )

    return try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportHandleFactory: { _ in
            SSHClientTransportHandle(transport: transport)
        }
    )
}

private func waitForBackgroundFailure(
    on transport: ConnectionFixtureMockSSHByteStreamTransport,
    baselineSentCount: Int
) async throws {
    let didSendKeepalive = await waitForSentPayloadCount(
        on: transport,
        minimumCount: baselineSentCount + 1,
        maxAttempts: backgroundKeepaliveObservationAttempts,
        sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
    )
    #expect(didSendKeepalive)

    let didCloseTransport = await waitUntil(
        maxAttempts: backgroundKeepaliveObservationAttempts,
        sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
    ) {
        await transport.closeCountObserved() == 1
    }
    #expect(didCloseTransport)
}
