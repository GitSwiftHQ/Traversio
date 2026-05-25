// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

private struct RemotePortForwardBodyFailure: Error, Equatable {}

@Test
func sshConnectionAcceptsForwardedTCPIPChannelsThroughRemotePortForwardListener() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    var allocatedPortWriter = SSHWireWriter()
    allocatedPortWriter.write(uint32: 47_000)
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: allocatedPortWriter.bytes))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: 47_000)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: 62001)
                    return writer.bytes
                }()
            )
        )
    )
    let inboundData = Array("PING".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            forwardedOpenPayload,
            dataPayload,
            eofPayload,
            closePayload,
            cancelSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let received = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withRemotePortForwardListener(
            remoteHost: "127.0.0.1",
            remotePort: 0
        ) { listener in
            #expect(listener.remoteHost == "127.0.0.1")
            #expect(listener.remotePort == 47_000)

            await Task.yield()

            let channel = try await listener.accept()
            #expect(channel.listeningHost == "127.0.0.1")
            #expect(channel.listeningPort == 47_000)
            #expect(channel.originatorHost == "198.51.100.7")
            #expect(channel.originatorPort == 62001)

            try await channel.write(Array("PONG".utf8))
            try await channel.sendEOF()

            let firstEvent = try await channel.nextEvent()
            let secondEvent = try await channel.nextEvent()
            let thirdEvent = try await channel.nextEvent()

            #expect(firstEvent == .data(inboundData))
            #expect(secondEvent == .endOfFile)
            #expect(thirdEvent == nil)

            return (data: inboundData, didReceiveEOF: secondEvent == .endOfFile)
        }
    }

    #expect(received.data == inboundData)
    #expect(received.didReceiveEOF)
    #expect(await transport.remainingReceiveChunkCount() == 0)
}

@Test
func sshConnectionAcceptsNextForwardedTCPIPChannelAfterLateCloseForPreviousChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(allocatedPort: 47_000)
    let firstForwardedOpenPayload = try forwardedTCPIPOpenPayload(
        senderChannel: 55,
        listeningPort: 47_000,
        originatorPort: 62_001
    )
    let firstInboundData = Array("FIRST".utf8)
    let firstDataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: firstInboundData
            )
        )
    )
    let firstClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let secondForwardedOpenPayload = try forwardedTCPIPOpenPayload(
        senderChannel: 56,
        listeningPort: 47_000,
        originatorPort: 62_002
    )
    let secondInboundData = Array("SECOND".utf8)
    let secondDataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: secondInboundData
            )
        )
    )
    let secondClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            firstForwardedOpenPayload,
            firstDataPayload,
            firstClosePayload,
            secondForwardedOpenPayload,
            secondDataPayload,
            secondClosePayload,
            cancelSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let received = try await withRemotePortForwardThrowingTestTimeout {
        try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.withRemotePortForwardListener(
                remoteHost: "127.0.0.1",
                remotePort: 0
            ) { listener in
                let firstChannel = try await listener.accept()
                let firstRead = try await firstChannel.readChunk()
                try await firstChannel.close()

                let secondChannel = try await listener.accept()
                #expect(secondChannel.originatorPort == 62_002)
                let secondRead = try await secondChannel.readChunk()
                try await secondChannel.close()

                return [
                    try #require(firstRead),
                    try #require(secondRead),
                ]
            }
        }
    }

    #expect(received == [firstInboundData, secondInboundData])
    #expect(await transport.remainingReceiveChunkCount() == 0)
}

@Test
func sshConnectionAcceptsForwardedStreamLocalChannelsThroughRemoteStreamLocalForwardListener() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let forwardedOpenPayload = try SSHConnectionMessageSerializer().serialize(
        SSHTCPIPForwardingRequestCoder().makeForwardedStreamLocalChannelOpen(
            senderChannel: 55,
            initialWindowSize: 1_048_576,
            maximumPacketSize: 32_768,
            request: SSHForwardedStreamLocalChannelOpenRequest(
                socketPath: "/tmp/traversio.sock"
            )
        )
    )
    let inboundData = Array("PING".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            forwardedOpenPayload,
            dataPayload,
            eofPayload,
            closePayload,
            cancelSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let received = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withRemoteStreamLocalForwardListener(
            socketPath: "/tmp/traversio.sock"
        ) { listener in
            #expect(listener.socketPath == "/tmp/traversio.sock")

            await Task.yield()

            let channel = try await listener.accept()
            #expect(channel.socketPath == "/tmp/traversio.sock")

            try await channel.write(Array("PONG".utf8))
            try await channel.sendEOF()

            let firstEvent = try await channel.nextEvent()
            let secondEvent = try await channel.nextEvent()
            let thirdEvent = try await channel.nextEvent()

            #expect(firstEvent == .data(inboundData))
            #expect(secondEvent == .endOfFile)
            #expect(thirdEvent == nil)

            return (data: inboundData, didReceiveEOF: secondEvent == .endOfFile)
        }
    }

    #expect(received.data == inboundData)
    #expect(received.didReceiveEOF)
    #expect(await transport.remainingReceiveChunkCount() == 0)
}

@Test
func sshConnectionRunsRemotePortForwardingLifecycle() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    var allocatedPortWriter = SSHWireWriter()
    allocatedPortWriter.write(uint32: 47_000)
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: allocatedPortWriter.bytes))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let activeForward: SSHRemotePortForward = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withRemotePortForwarding(
            localPort: 8080,
            remoteHost: "127.0.0.1",
            remotePort: 0
        ) { forward in
            #expect(forward.localHost == "127.0.0.1")
            #expect(forward.localPort == 8080)
            #expect(forward.remoteHost == "127.0.0.1")
            #expect(forward.remotePort == 47_000)
            return forward
        }
    }

    #expect(
        activeForward == SSHRemotePortForward(
            localHost: "127.0.0.1",
            localPort: 8080,
            remoteHost: "127.0.0.1",
            remotePort: 47_000
        )
    )
    #expect(await transport.remainingReceiveChunkCount() == 0)
}

@Test
func sshRemotePortForwardingScopeCancellationLeavesConnectionUsable() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstRequestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let firstCancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let secondRequestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_001
    )
    let secondCancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstRequestSuccessPayload,
            firstCancelSuccessPayload,
            secondRequestSuccessPayload,
            secondCancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let ready = RemoteForwardReadyProbe()
    let service = SSHRemotePortForwardService(
        client: fixture.client,
        requestedForward: SSHRemotePortForward(
            localHost: "127.0.0.1",
            localPort: 9,
            remoteHost: "127.0.0.1",
            remotePort: 0
        ),
        lifetime: SSHConnectionLifetime(),
        metadata: testConnectionMetadata(),
        logHandler: .disabled,
        bridgeHandler: { _, _ in }
    )
    let scopeTask = Task {
        try await service.withForward { forward in
            await ready.succeed(forward)
            try await Task.sleep(nanoseconds: 60_000_000_000)
        }
    }

    let activeForward = try await withRemotePortForwardThrowingTestTimeout {
        try await ready.value()
    }
    #expect(activeForward.remotePort == 47_000)

    scopeTask.cancel()
    do {
        try await withRemotePortForwardThrowingTestTimeout {
            try await scopeTask.value
        }
        Issue.record("Expected the remote forwarding scope task to be cancelled.")
    } catch is CancellationError {
    }

    let secondForward = try await withRemotePortForwardThrowingTestTimeout {
        try await fixture.client.requestTCPIPForward(
            addressToBind: "127.0.0.1",
            portToBind: 0
        )
    }
    #expect(secondForward.portToBind == 47_001)
    try await fixture.client.cancelTCPIPForward(secondForward)
    #expect(await fixture.transport.remainingReceiveChunkCount() == 0)
}

@Test
func sshRemotePortForwardListenerPreservesBodyErrorWhenCancelClosesLifetime() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let operationCanceled = try #require(POSIXErrorCode(rawValue: 89))

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let service = SSHRemotePortForwardListenerService(
        client: fixture.client,
        requestedForward: SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 0
        ),
        lifetime: SSHConnectionLifetime(),
        metadata: testConnectionMetadata(),
        logHandler: .disabled
    )

    do {
        _ = try await service.withListener { listener in
            #expect(listener.remotePort == 47_000)
            await fixture.transport.enqueueSendFailure(operationCanceled)
            throw RemotePortForwardBodyFailure()
        }
        Issue.record("Expected the listener body failure to be thrown.")
    } catch {
        #expect(error as? RemotePortForwardBodyFailure == RemotePortForwardBodyFailure())
    }
}

@Test
func sshRemotePortForwardListenerPreservesBodyErrorWhenCancelRequestIsRejected() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let requestFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            requestFailurePayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let lifetime = SSHConnectionLifetime()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    let service = SSHRemotePortForwardListenerService(
        client: fixture.client,
        requestedForward: SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 0
        ),
        lifetime: lifetime,
        metadata: testConnectionMetadata(),
        logHandler: .disabled
    )

    do {
        _ = try await service.withListener { listener in
            #expect(listener.remotePort == 47_000)
            throw RemotePortForwardBodyFailure()
        }
        Issue.record("Expected the listener body failure to be thrown.")
    } catch {
        #expect(error as? RemotePortForwardBodyFailure == RemotePortForwardBodyFailure())
    }

    #expect(!(await lifetime.active()))
}

@Test
func sshConnectionClosesLifetimeAfterRemoteForwardShutdownTransportError() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    var allocatedPortWriter = SSHWireWriter()
    allocatedPortWriter.write(uint32: 47_000)
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: allocatedPortWriter.bytes))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let operationCanceled = try #require(POSIXErrorCode(rawValue: 89))

    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let allocatedPort = try await connection.withRemotePortForwardListener(
            remoteHost: "127.0.0.1",
            remotePort: 0
        ) { listener in
            await transport.enqueueSendFailure(operationCanceled)
            return listener.remotePort
        }
        #expect(allocatedPort == 47_000)

        do {
            _ = try await connection.withRemotePortForwardListener(
                remoteHost: "127.0.0.1",
                remotePort: 0
            ) { _ in
                0
            }
            Issue.record("Expected the connection lifetime to close after shutdown transport error.")
        } catch {
            #expect(error as? SSHClientError == .connectionScopeEnded)
        }
    }
}

@Test
func sshConnectionClosesLifetimeAfterRemoteForwardCancelRequestFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let requestFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            requestFailurePayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        do {
            _ = try await connection.withRemotePortForwardListener(
                remoteHost: "127.0.0.1",
                remotePort: 0
            ) { listener in
                listener.remotePort
            }
            Issue.record("Expected the cancel request rejection to surface as a public failure.")
        } catch {
            let failure = try #require({
                if case let .operationFailed(value)? = error as? SSHClientError {
                    return value
                }
                return nil
            }())
            #expect(failure.scope == .remotePortForwardListener)
            #expect(failure.code == .requestFailed)
            #expect(failure.diagnostics.requestType == "cancel-tcpip-forward")
        }

        do {
            _ = try await connection.execute("true")
            Issue.record("Expected the connection lifetime to close after cancel request rejection.")
        } catch {
            #expect(error as? SSHClientError == .connectionScopeEnded)
        }
    }
}

@Test
func sshRemotePortForwardListenerStopsAfterBackgroundKeepaliveFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval)
    )
    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let postConnectSentCount = await transport.sentPayloads().count

    var escapedListener: SSHRemotePortForwardListener?
    var sentPayloadCountAtBackgroundFailure: Int?
    do {
        try await connection.withRemotePortForwardListener(
            remoteHost: "127.0.0.1",
            remotePort: 0
        ) { listener in
            escapedListener = listener
            #expect(listener.remotePort == 47_000)

            #expect(
                await waitUntil(
                    maxAttempts: backgroundKeepaliveObservationAttempts,
                    sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
                ) {
                    await transport.closeCountObserved() == 1
                }
            )
            sentPayloadCountAtBackgroundFailure = await transport.sentPayloads().count
        }
        Issue.record("Expected remote forwarding listener scope to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    let listener = try #require(escapedListener)
    let failedSentCount = try #require(sentPayloadCountAtBackgroundFailure)
    #expect(failedSentCount > postConnectSentCount)
    #expect(await transport.sentPayloads().count == failedSentCount)

    do {
        _ = try await listener.accept()
        Issue.record("Expected remote forwarding listener accepts to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
    #expect(await transport.sentPayloads().count == failedSentCount)

    await connection.close()
}

@Test
func sshRemoteStreamLocalForwardListenerStopsAfterBackgroundKeepaliveFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval)
    )
    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let postConnectSentCount = await transport.sentPayloads().count

    var escapedListener: SSHRemoteStreamLocalForwardListener?
    var sentPayloadCountAtBackgroundFailure: Int?
    do {
        try await connection.withRemoteStreamLocalForwardListener(
            socketPath: "/tmp/traversio.sock"
        ) { listener in
            escapedListener = listener
            #expect(listener.socketPath == "/tmp/traversio.sock")

            #expect(
                await waitUntil(
                    maxAttempts: backgroundKeepaliveObservationAttempts,
                    sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
                ) {
                    await transport.closeCountObserved() == 1
                }
            )
            sentPayloadCountAtBackgroundFailure = await transport.sentPayloads().count
        }
        Issue.record("Expected streamlocal forwarding listener scope to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    let listener = try #require(escapedListener)
    let failedSentCount = try #require(sentPayloadCountAtBackgroundFailure)
    #expect(failedSentCount > postConnectSentCount)
    #expect(await transport.sentPayloads().count == failedSentCount)

    do {
        _ = try await listener.accept()
        Issue.record("Expected streamlocal forwarding listener accepts to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
    #expect(await transport.sentPayloads().count == failedSentCount)

    await connection.close()
}

@Test
func sshRemotePortForwardingServiceKeepsListenerAliveAfterOneAcceptedConnectionFails() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            try forwardedTCPIPOpenPayload(
                senderChannel: 55,
                listeningPort: 47_000,
                originatorPort: 62_001
            ),
            try forwardedTCPIPOpenPayload(
                senderChannel: 56,
                listeningPort: 47_000,
                originatorPort: 62_002
            ),
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try await withLoopbackTCPServer { localPort in
        let bridgeProbe = RemoteBridgeFailureProbe()
        let service = SSHRemotePortForwardService(
            client: fixture.client,
            requestedForward: SSHRemotePortForward(
                localHost: "127.0.0.1",
                localPort: localPort,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ),
            lifetime: SSHConnectionLifetime(),
            metadata: testConnectionMetadata(),
            logHandler: .disabled,
            bridgeHandler: { _, remoteChannel in
                try await bridgeProbe.handle(remoteChannel)
            }
        )

        let activeForward = try await service.withForward { forward in
            #expect(forward.localHost == "127.0.0.1")
            #expect(forward.localPort == localPort)
            #expect(forward.remoteHost == "127.0.0.1")
            #expect(forward.remotePort == 47_000)

            try await withRemotePortForwardTestTimeout {
                await bridgeProbe.waitForInvocationCount(2)
            }

            return forward
        }

        let snapshot = await bridgeProbe.snapshot()
        #expect(activeForward.remotePort == 47_000)
        #expect(snapshot.invocationCount == 2)
        #expect(snapshot.channelIDs.sorted() == [0, 1])
    }
}

@Test
func sshRemotePortForwardingServiceKeepsListenerAliveAfterTransportClassifiedBridgeFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            try forwardedTCPIPOpenPayload(
                senderChannel: 55,
                listeningPort: 47_000,
                originatorPort: 62_011
            ),
            try forwardedTCPIPOpenPayload(
                senderChannel: 56,
                listeningPort: 47_000,
                originatorPort: 62_012
            ),
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try await withLoopbackTCPServer { localPort in
        let bridgeProbe = RemoteBridgeTransportFailureProbe()
        let lifetime = SSHConnectionLifetime()
        let service = SSHRemotePortForwardService(
            client: fixture.client,
            requestedForward: SSHRemotePortForward(
                localHost: "127.0.0.1",
                localPort: localPort,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ),
            lifetime: lifetime,
            metadata: testConnectionMetadata(),
            logHandler: .disabled,
            bridgeHandler: { _, remoteChannel in
                try await bridgeProbe.handle(remoteChannel)
            }
        )

        let activeForward = try await service.withForward { forward in
            #expect(forward.remotePort == 47_000)

            try await withRemotePortForwardTestTimeout {
                await bridgeProbe.waitForInvocationCount(2)
            }

            return forward
        }

        let snapshot = await bridgeProbe.snapshot()
        #expect(activeForward.remotePort == 47_000)
        #expect(snapshot.invocationCount == 2)
        #expect(await lifetime.active())
    }
}

@Test
func sshRemotePortForwardingServiceBridgesAcceptedConnectionsConcurrently() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            try forwardedTCPIPOpenPayload(
                senderChannel: 55,
                listeningPort: 47_000,
                originatorPort: 62_101
            ),
            try forwardedTCPIPOpenPayload(
                senderChannel: 56,
                listeningPort: 47_000,
                originatorPort: 62_102
            ),
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try await withLoopbackTCPServer { localPort in
        let bridgeProbe = RemoteBridgeConcurrencyProbe()
        let service = SSHRemotePortForwardService(
            client: fixture.client,
            requestedForward: SSHRemotePortForward(
                localHost: "127.0.0.1",
                localPort: localPort,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ),
            lifetime: SSHConnectionLifetime(),
            metadata: testConnectionMetadata(),
            logHandler: .disabled,
            bridgeHandler: { _, remoteChannel in
                try await bridgeProbe.handle(remoteChannel)
            }
        )

        let activeForward = try await service.withForward { forward in
            #expect(forward.localPort == localPort)
            #expect(forward.remotePort == 47_000)

            try await withRemotePortForwardTestTimeout {
                await bridgeProbe.waitUntilConcurrentBridgesObserved()
            }

            await bridgeProbe.releaseAll()
            return forward
        }

        #expect(activeForward.remotePort == 47_000)
        #expect(await bridgeProbe.maximumActiveBridgeCountObserved() == 2)
    }
}

@Test
func sshRemotePortForwardingServiceDeliversAcceptedChannelDataWhileAcceptLoopStaysArmed() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let inboundData = Array("remote-bridge-data".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            try forwardedTCPIPOpenPayload(
                senderChannel: 55,
                listeningPort: 47_000,
                originatorPort: 62_103
            ),
            dataPayload,
            eofPayload,
            closePayload,
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try await withLoopbackTCPServer { localPort in
        let bridgeProbe = RemoteBridgeReadProbe(expectedPayload: inboundData)
        let service = SSHRemotePortForwardService(
            client: fixture.client,
            requestedForward: SSHRemotePortForward(
                localHost: "127.0.0.1",
                localPort: localPort,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ),
            lifetime: SSHConnectionLifetime(),
            metadata: testConnectionMetadata(),
            logHandler: .disabled,
            bridgeHandler: { _, remoteChannel in
                try await bridgeProbe.handle(remoteChannel)
            }
        )

        _ = try await service.withForward { forward in
            #expect(forward.remotePort == 47_000)

            try await withRemotePortForwardTestTimeout {
                await bridgeProbe.waitUntilReadCompletes()
            }
        }

        #expect(await bridgeProbe.didReceiveExpectedPayload())
    }
}

@Test
func sshRemotePortForwardingServiceDeliversAcceptedChannelDataBeforeRemoteEOF() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestSuccessPayload = try remoteForwardRequestSuccessPayload(
        allocatedPort: 47_000
    )
    let inboundData = Array("remote-bridge-data-without-eof".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: inboundData
            )
        )
    )
    let cancelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestSuccessPayload,
            try forwardedTCPIPOpenPayload(
                senderChannel: 55,
                listeningPort: 47_000,
                originatorPort: 62_104
            ),
            dataPayload,
            cancelSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try await withLoopbackTCPServer { localPort in
        let bridgeProbe = RemoteBridgeReadProbe(expectedPayload: inboundData)
        let service = SSHRemotePortForwardService(
            client: fixture.client,
            requestedForward: SSHRemotePortForward(
                localHost: "127.0.0.1",
                localPort: localPort,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ),
            lifetime: SSHConnectionLifetime(),
            metadata: testConnectionMetadata(),
            logHandler: .disabled,
            bridgeHandler: { _, remoteChannel in
                try await bridgeProbe.handle(remoteChannel)
            }
        )

        _ = try await service.withForward { forward in
            #expect(forward.remotePort == 47_000)

            try await withRemotePortForwardTestTimeout {
                await bridgeProbe.waitUntilReadCompletes()
            }
        }

        #expect(await bridgeProbe.didReceiveExpectedPayload())
    }
}

private enum RemotePortForwardTestError: Error {
    case syntheticBridgeFailure
    case timedOut
}

private actor RemoteForwardReadyProbe {
    private var continuation: CheckedContinuation<SSHRemotePortForward, Error>?
    private var result: Result<SSHRemotePortForward, Error>?

    func value() async throws -> SSHRemotePortForward {
        if let result {
            return try result.get()
        }

        return try await withCheckedThrowingContinuation { continuation in
            precondition(self.continuation == nil, "remote forward readiness already waiting")
            self.continuation = continuation
        }
    }

    func succeed(_ forward: SSHRemotePortForward) {
        guard self.result == nil else {
            return
        }

        self.result = .success(forward)
        self.continuation?.resume(returning: forward)
        self.continuation = nil
    }
}

private actor RemoteBridgeFailureProbe {
    struct Snapshot: Equatable {
        let invocationCount: Int
        let channelIDs: [UInt32]
    }

    private var invocationCount = 0
    private var channelIDs: [UInt32] = []
    private var invocationContinuation: CheckedContinuation<Void, Never>?

    func handle(_ remoteChannel: SSHTCPIPChannelHandle) async throws {
        self.invocationCount += 1
        self.channelIDs.append(remoteChannel.channel.localChannelID)

        if self.invocationCount >= 2 {
            self.invocationContinuation?.resume()
            self.invocationContinuation = nil
        }

        if self.invocationCount == 1 {
            throw RemotePortForwardTestError.syntheticBridgeFailure
        }

        try await remoteChannel.close()
    }

    func waitForInvocationCount(_ expectedCount: Int) async {
        guard self.invocationCount < expectedCount else {
            return
        }

        await withCheckedContinuation { continuation in
            self.invocationContinuation = continuation
        }
    }

    func snapshot() -> Snapshot {
        Snapshot(
            invocationCount: self.invocationCount,
            channelIDs: self.channelIDs
        )
    }
}

private actor RemoteBridgeTransportFailureProbe {
    struct Snapshot: Equatable {
        let invocationCount: Int
        let channelIDs: [UInt32]
    }

    private var invocationCount = 0
    private var channelIDs: [UInt32] = []
    private var invocationContinuation: CheckedContinuation<Void, Never>?

    func handle(_ remoteChannel: SSHTCPIPChannelHandle) async throws {
        self.invocationCount += 1
        self.channelIDs.append(remoteChannel.channel.localChannelID)

        if self.invocationCount >= 2 {
            self.invocationContinuation?.resume()
            self.invocationContinuation = nil
        }

        if self.invocationCount == 1 {
            throw SSHTransportError.endOfStreamBeforePacket
        }

        try await remoteChannel.close()
    }

    func waitForInvocationCount(_ expectedCount: Int) async {
        guard self.invocationCount < expectedCount else {
            return
        }

        await withCheckedContinuation { continuation in
            self.invocationContinuation = continuation
        }
    }

    func snapshot() -> Snapshot {
        Snapshot(
            invocationCount: self.invocationCount,
            channelIDs: self.channelIDs
        )
    }
}

private actor RemoteBridgeConcurrencyProbe {
    private var activeBridgeCount = 0
    private var maximumActiveBridgeCount = 0
    private var isReleased = false
    private var concurrentBridgeContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuations: [CheckedContinuation<Void, Never>] = []

    func handle(_ remoteChannel: SSHTCPIPChannelHandle) async throws {
        self.activeBridgeCount += 1
        self.maximumActiveBridgeCount = max(
            self.maximumActiveBridgeCount,
            self.activeBridgeCount
        )

        if self.maximumActiveBridgeCount >= 2 {
            self.concurrentBridgeContinuation?.resume()
            self.concurrentBridgeContinuation = nil
        }

        if !self.isReleased {
            await withCheckedContinuation { continuation in
                self.releaseContinuations.append(continuation)
            }
        }

        self.activeBridgeCount -= 1
        try await remoteChannel.close()
    }

    func waitUntilConcurrentBridgesObserved() async {
        guard self.maximumActiveBridgeCount < 2 else {
            return
        }

        await withCheckedContinuation { continuation in
            self.concurrentBridgeContinuation = continuation
        }
    }

    func releaseAll() {
        self.isReleased = true
        let continuations = self.releaseContinuations
        self.releaseContinuations.removeAll(keepingCapacity: false)

        for continuation in continuations {
            continuation.resume()
        }
    }

    func maximumActiveBridgeCountObserved() -> Int {
        self.maximumActiveBridgeCount
    }
}

private actor RemoteBridgeReadProbe {
    private let expectedPayload: [UInt8]
    private var receivedPayload: [UInt8]?
    private var completionContinuation: CheckedContinuation<Void, Never>?

    init(expectedPayload: [UInt8]) {
        self.expectedPayload = expectedPayload
    }

    func handle(_ remoteChannel: SSHTCPIPChannelHandle) async throws {
        let receivedPayload = try await remoteChannel.readChunk()
        self.receivedPayload = receivedPayload
        self.completionContinuation?.resume()
        self.completionContinuation = nil
    }

    func waitUntilReadCompletes() async {
        guard self.receivedPayload == nil else {
            return
        }

        await withCheckedContinuation { continuation in
            self.completionContinuation = continuation
        }
    }

    func didReceiveExpectedPayload() -> Bool {
        self.receivedPayload == self.expectedPayload
    }
}

private func withLoopbackTCPServer<Result>(
    host: String = "127.0.0.1",
    _ body: (UInt16) async throws -> Result
) async throws -> Result {
    let listener = try SSHTCPListenerFactory.makeListener(localHost: host, localPort: 0)

    let listenerTask = Task {
        try await listener.run { localConnection in
            await localConnection.close()
        }
    }

    let localPort: UInt16
    do {
        localPort = try await listener.readyPort()
    } catch {
        listenerTask.cancel()
        _ = try? await listenerTask.value
        throw error
    }

    do {
        let result = try await body(localPort)
        listenerTask.cancel()
        _ = try? await listenerTask.value
        return result
    } catch {
        listenerTask.cancel()
        _ = try? await listenerTask.value
        throw error
    }
}

private func testConnectionMetadata() -> SSHConnectionMetadata {
    SSHConnectionMetadata(
        endpointHost: "example.com",
        endpointPort: 22,
        username: "root",
        clientIdentification: "SSH-2.0-TraversioTests",
        remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
        preIdentificationLines: [],
        hostKeyAlgorithm: "ssh-ed25519",
        hostKeyFingerprintSHA256: "SHA256:test-host-key",
        hostKeyTrustMethod: .acceptAnyVerifiedHostKey
    )
}

private func remoteForwardRequestSuccessPayload(
    allocatedPort: UInt32
) throws -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(uint32: allocatedPort)
    return try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: writer.bytes))
    )
}

private func forwardedTCPIPOpenPayload(
    senderChannel: UInt32,
    listeningPort: UInt32,
    originatorPort: UInt32
) throws -> [UInt8] {
    try SSHConnectionMessageSerializer().serialize(
        .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: senderChannel,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: {
                    var writer = SSHWireWriter()
                    writer.write(utf8: "127.0.0.1")
                    writer.write(uint32: listeningPort)
                    writer.write(utf8: "198.51.100.7")
                    writer.write(uint32: originatorPort)
                    return writer.bytes
                }()
            )
        )
    )
}

private func withRemotePortForwardTestTimeout(
    nanoseconds: UInt64 = 1_000_000_000,
    _ operation: @escaping @Sendable () async -> Void
) async throws {
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
            await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            throw RemotePortForwardTestError.timedOut
        }

        let _ = try await group.next()
        group.cancelAll()
        while let _ = try? await group.next() {}
    }
}

private func withRemotePortForwardThrowingTestTimeout<Result: Sendable>(
    nanoseconds: UInt64 = 2_000_000_000,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    try await withThrowingTaskGroup(of: Result.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            throw RemotePortForwardTestError.timedOut
        }

        let result = try await group.next()!
        group.cancelAll()
        while let _ = try? await group.next() {}
        return result
    }
}
