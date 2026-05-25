// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

private enum LocalForwardPostScopeAttemptOutcome: Equatable {
    case refused
    case closed
    case receivedData([UInt8])
    case timedOut
}

private actor LocalForwardEndpointRecorder {
    private var endpoint: SSHSocketEndpoint?

    func record(_ endpoint: SSHSocketEndpoint) {
        self.endpoint = endpoint
    }

    func current() -> SSHSocketEndpoint? {
        self.endpoint
    }
}

@Test
func sshConnectionRunsLocalPortForwardingOnLoopback() async throws {
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
    let inboundData = Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
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
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedForward: SSHLocalPortForward?
    let response: [UInt8] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withLocalPortForwarding(
            targetHost: "db.internal",
            targetPort: 5432
        ) { forward in
            escapedForward = forward

            #expect(forward.localHost == "127.0.0.1")
            #expect(forward.localPort != 0)
            #expect(forward.targetHost == "db.internal")
            #expect(forward.targetPort == 5432)

            return try await SSHTCPByteStreamTransportFactory.withConnected(
                to: SSHSocketEndpoint(host: forward.localHost, port: forward.localPort)
            ) { localTransport in
                var response: [UInt8] = []
                while true {
                    let chunk = try await localTransport.receive(
                        atLeast: 1,
                        atMost: 4096
                    )
                    response += chunk.bytes

                    if chunk.endOfStream {
                        return response
                    }
                }
            }
        }
    }

    #expect(response == inboundData)
    #expect(try #require(escapedForward).localPort != 0)
}

@Test
func sshConnectionStopsBridgingLateLocalForwardConnectionsAfterScopeEnds() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var localEndpoint: SSHSocketEndpoint?
    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
        ) { connection in
        try await connection.withLocalPortForwarding(
            targetHost: "db.internal",
            targetPort: 5432
        ) { forward in
            localEndpoint = SSHSocketEndpoint(
                host: forward.localHost,
                port: forward.localPort
            )
        }
    }

    let endpoint = try #require(localEndpoint)
    let sentPayloadCountBefore = await transport.sentPayloads().count
    let didStopAccepting = await localForwardEventuallyStopsAfterScope(to: endpoint)
    let sentPayloadCountAfter = await transport.sentPayloads().count

    #expect(didStopAccepting)
    #expect(sentPayloadCountAfter == sentPayloadCountBefore)
}

@Test
func sshConnectionStopsLocalPortForwardingAfterBackgroundKeepaliveFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
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

    var localEndpoint: SSHSocketEndpoint?
    do {
        try await connection.withLocalPortForwarding(
            targetHost: "db.internal",
            targetPort: 5432
        ) { forward in
            localEndpoint = SSHSocketEndpoint(
                host: forward.localHost,
                port: forward.localPort
            )
            #expect(
                await waitUntil(
                    maxAttempts: backgroundKeepaliveObservationAttempts,
                    sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
                ) {
                    await transport.closeCountObserved() == 1
                }
            )
        }
        Issue.record("Expected local forwarding scope to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    let endpoint = try #require(localEndpoint)
    let sentPayloadCountBefore = await transport.sentPayloads().count
    #expect(sentPayloadCountBefore > postConnectSentCount)
    let didStopAccepting = await localForwardEventuallyStopsAfterScope(to: endpoint)
    let sentPayloadCountAfter = await transport.sentPayloads().count

    #expect(didStopAccepting)
    #expect(sentPayloadCountAfter == sentPayloadCountBefore)

    await connection.close()
}

@Test
func sshConnectionKeepsLocalPortForwardListenerAliveAfterOneAcceptedConnectionFails() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstOpenFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenFailure(
            SSHChannelOpenFailureMessage(
                recipientChannel: 0,
                reasonCode: .connectFailed,
                description: "connection refused",
                languageTag: "en-US"
            )
        )
    )
    let secondOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 92,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let inboundData = Array("local-forward-still-alive".utf8)
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: inboundData
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            firstOpenFailurePayload,
            secondOpenConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let response: [UInt8] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withLocalPortForwarding(
            targetHost: "db.internal",
            targetPort: 5432
        ) { forward in
            let endpoint = SSHSocketEndpoint(
                host: forward.localHost,
                port: forward.localPort
            )

            let firstOutcome = await localForwardPostScopeAttemptOutcome(to: endpoint)
            #expect(firstOutcome == .closed)

            return try await SSHTCPByteStreamTransportFactory.withConnected(
                to: endpoint
            ) { localTransport in
                var response: [UInt8] = []
                while true {
                    let chunk = try await localTransport.receive(
                        atLeast: 1,
                        atMost: 4096
                    )
                    response += chunk.bytes

                    if chunk.endOfStream {
                        return response
                    }
                }
            }
        }
    }

    #expect(response == inboundData)
}

@Test
func sshConnectionReleasesLocalPortForwardListenerAfterConnectionLivenessLoss() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(responseTimeInterval: 0.05)
    )
    let endpointRecorder = LocalForwardEndpointRecorder()

    let forwardingTask = Task {
        try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.withLocalPortForwarding(
                targetHost: "db.internal",
                targetPort: 5432
            ) { forward in
                await endpointRecorder.record(
                    SSHSocketEndpoint(
                        host: forward.localHost,
                        port: forward.localPort
                    )
                )

                try await Task.sleep(nanoseconds: 300_000_000)
            }
        }
    }

    #expect(
        await waitUntil(
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        ) {
            await endpointRecorder.current() != nil
        }
    )
    let endpoint = try #require(await endpointRecorder.current())

    #expect(
        await waitUntil(
            maxAttempts: 100,
            sleepNanoseconds: 5_000_000
        ) {
            let outcome = await localForwardPostScopeAttemptOutcome(to: endpoint)
            return outcome == .refused || outcome == .closed
        }
    )

    do {
        try await forwardingTask.value
        Issue.record("Expected local port forwarding scope to end after connection liveness loss.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    #expect(await transport.closeCountObserved() == 1)
}

private func localForwardEventuallyStopsAfterScope(
    to endpoint: SSHSocketEndpoint,
    maxAttempts: Int = 100,
    sleepNanoseconds: UInt64 = 5_000_000
) async -> Bool {
    for _ in 0..<maxAttempts {
        switch await localForwardPostScopeAttemptOutcome(to: endpoint) {
        case .refused, .closed:
            return true
        case .receivedData:
            return false
        case .timedOut:
            break
        }

        try? await Task.sleep(nanoseconds: sleepNanoseconds)
        await Task.yield()
    }

    return false
}

private func localForwardPostScopeAttemptOutcome(
    to endpoint: SSHSocketEndpoint
) async -> LocalForwardPostScopeAttemptOutcome {
    await withTaskGroup(of: LocalForwardPostScopeAttemptOutcome.self) { group in
        group.addTask {
            do {
                return try await localForwardReceiveChunkOutcome(from: endpoint)
            } catch {
                return .refused
            }
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: 500_000_000)
            return .timedOut
        }

        guard let outcome = await group.next() else {
            fatalError("local forward connection attempt returned no outcome")
        }

        group.cancelAll()
        return outcome
    }
}

private func localForwardReceiveChunkOutcome(
    from endpoint: SSHSocketEndpoint
) async throws -> LocalForwardPostScopeAttemptOutcome {
    try await SSHTCPByteStreamTransportFactory.withConnected(to: endpoint) { transport in
        let chunk = try await transport.receive(atLeast: 1, atMost: 4096)
        if chunk.endOfStream && chunk.bytes.isEmpty {
            return .closed
        }
        return .receivedData(chunk.bytes)
    }
}
