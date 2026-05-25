// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

private enum DynamicForwardPostScopeAttemptOutcome: Equatable {
    case refused
    case closed
    case receivedData([UInt8])
    case timedOut
}

private actor DynamicForwardEndpointRecorder {
    private var endpoint: SSHSocketEndpoint?

    func record(_ endpoint: SSHSocketEndpoint) {
        self.endpoint = endpoint
    }

    func current() -> SSHSocketEndpoint? {
        self.endpoint
    }
}

@Test
func sshConnectionRunsDynamicPortForwardingOverSOCKS5() async throws {
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
    let inboundData = Array("dynamic-forward-ok".utf8)
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

    let response = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withDynamicPortForwarding { forward in
            return try await SSHTCPByteStreamTransportFactory.withConnected(
                to: SSHSocketEndpoint(host: forward.localHost, port: forward.localPort)
            ) { localTransport in
                try await localTransport.send([0x05, 0x01, 0x00], endOfStream: false)
                #expect(
                    try await readExactByteCount(2, from: localTransport)
                        == [0x05, 0x00]
                )

                let hostBytes = Array("db.internal".utf8)
                var request = [UInt8(0x05), 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
                request += hostBytes
                request += [0x15, 0x38]
                try await localTransport.send(request, endOfStream: false)

                let reply = try await readExactByteCount(10, from: localTransport)
                #expect(reply == [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

                var received: [UInt8] = []
                while true {
                    let chunk = try await localTransport.receive(atLeast: 1, atMost: 4096)
                    received += chunk.bytes
                    if chunk.endOfStream {
                        return received
                    }
                }
            }
        }
    }

    #expect(response == inboundData)
}

@Test
func sshConnectionRunsDynamicPortForwardingOverSOCKS5WithUsernamePasswordAuthentication() async throws {
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
    let inboundData = Array("dynamic-forward-auth-ok".utf8)
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

    let usernameBytes = Array("alice".utf8)
    let passwordBytes = Array("p@ssw0rd".utf8)

    let response = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withDynamicPortForwarding(
            socks5Authentication: .usernamePassword(
                username: "alice",
                password: "p@ssw0rd"
            )
        ) { forward in
            return try await SSHTCPByteStreamTransportFactory.withConnected(
                to: SSHSocketEndpoint(host: forward.localHost, port: forward.localPort)
            ) { localTransport in
                try await localTransport.send([0x05, 0x01, 0x02], endOfStream: false)
                #expect(
                    try await readExactByteCount(2, from: localTransport)
                        == [0x05, 0x02]
                )

                try await localTransport.send(
                    [0x01, UInt8(usernameBytes.count)] +
                        usernameBytes +
                        [UInt8(passwordBytes.count)] +
                        passwordBytes,
                    endOfStream: false
                )
                #expect(
                    try await readExactByteCount(2, from: localTransport)
                        == [0x01, 0x00]
                )

                let hostBytes = Array("db.internal".utf8)
                var request = [UInt8(0x05), 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
                request += hostBytes
                request += [0x15, 0x38]
                try await localTransport.send(request, endOfStream: false)

                let reply = try await readExactByteCount(10, from: localTransport)
                #expect(reply == [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

                var received: [UInt8] = []
                while true {
                    let chunk = try await localTransport.receive(atLeast: 1, atMost: 4096)
                    received += chunk.bytes
                    if chunk.endOfStream {
                        return received
                    }
                }
            }
        }
    }

    #expect(response == inboundData)
}

@Test
func sshConnectionRejectsInvalidDynamicSOCKS5CredentialsBeforeListening() async throws {
    let transport = try makeAuthenticatedConnectionFixtureTransport()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.withDynamicPortForwarding(
                socks5Authentication: .usernamePassword(
                    username: "",
                    password: "secret"
                )
            ) { _ in
                Issue.record("Expected invalid SOCKS5 credentials to fail before binding.")
            }
        }
        Issue.record("Expected invalid SOCKS5 credentials to fail.")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .localPortForward)
        #expect(failure.code == .transportError)
        #expect(failure.message == "SOCKS5 username/password authentication requires a non-empty username.")
    }
}

@Test
func sshConnectionRejectsSOCKS4PerConnectionWhenDynamicSOCKS5AuthenticationIsConfigured() async throws {
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
    let inboundData = Array("dynamic-forward-socks4-rejected".utf8)
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

    let response = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.withDynamicPortForwarding(
            socks5Authentication: .usernamePassword(
                username: "alice",
                password: "secret"
            )
        ) { forward in
            try await SSHTCPByteStreamTransportFactory.withConnected(
                to: SSHSocketEndpoint(host: forward.localHost, port: forward.localPort)
            ) { localTransport in
                try await localTransport.send(
                    [0x04, 0x01, 0x15, 0x38, 127, 0, 0, 1, 0x00],
                    endOfStream: false
                )
                #expect(
                    try await readExactByteCount(8, from: localTransport)
                        == [0x00, 0x5b, 0, 0, 0, 0, 0, 0]
                )
            }

            return try await SSHTCPByteStreamTransportFactory.withConnected(
                to: SSHSocketEndpoint(host: forward.localHost, port: forward.localPort)
            ) { localTransport in
                try await localTransport.send([0x05, 0x01, 0x02], endOfStream: false)
                #expect(
                    try await readExactByteCount(2, from: localTransport)
                        == [0x05, 0x02]
                )

                let usernameBytes = Array("alice".utf8)
                let passwordBytes = Array("secret".utf8)
                try await localTransport.send(
                    [0x01, UInt8(usernameBytes.count)] +
                        usernameBytes +
                        [UInt8(passwordBytes.count)] +
                        passwordBytes,
                    endOfStream: false
                )
                #expect(
                    try await readExactByteCount(2, from: localTransport)
                        == [0x01, 0x00]
                )

                let hostBytes = Array("db.internal".utf8)
                var request = [UInt8(0x05), 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
                request += hostBytes
                request += [0x15, 0x38]
                try await localTransport.send(request, endOfStream: false)

                let reply = try await readExactByteCount(10, from: localTransport)
                #expect(reply == [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

                var received: [UInt8] = []
                while true {
                    let chunk = try await localTransport.receive(atLeast: 1, atMost: 4096)
                    received += chunk.bytes
                    if chunk.endOfStream {
                        return received
                    }
                }
            }
        }
    }

    #expect(response == inboundData)
}

@Test
func sshConnectionReleasesDynamicPortForwardListenerAfterConnectionLivenessLoss() async throws {
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
    let endpointRecorder = DynamicForwardEndpointRecorder()

    let forwardingTask = Task {
        try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.withDynamicPortForwarding { forward in
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

    #expect(await dynamicForwardEventuallyStopsAfterScope(to: endpoint))

    do {
        try await forwardingTask.value
        Issue.record("Expected dynamic port forwarding scope to end after connection liveness loss.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    let sentPayloadCountBefore = await transport.sentPayloads().count
    let didStopAccepting = await dynamicForwardEventuallyStopsAfterScope(to: endpoint)
    let sentPayloadCountAfter = await transport.sentPayloads().count

    #expect(didStopAccepting)
    #expect(sentPayloadCountAfter == sentPayloadCountBefore)
    #expect(await transport.closeCountObserved() == 1)
}

private func readExactByteCount(
    _ count: Int,
    from transport: any SSHByteStreamTransport
) async throws -> [UInt8] {
    var bytes: [UInt8] = []

    while bytes.count < count {
        let chunk = try await transport.receive(
            atLeast: 1,
            atMost: count - bytes.count
        )
        bytes += chunk.bytes
    }

    return bytes
}

private func makeAuthenticatedConnectionFixtureTransport() throws
    -> any SSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )

    return try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
}

private func operationFailure(from error: any Error) -> SSHOperationFailure? {
    guard case let .operationFailed(failure)? = error as? SSHClientError else {
        return nil
    }

    return failure
}

private func dynamicForwardEventuallyStopsAfterScope(
    to endpoint: SSHSocketEndpoint,
    maxAttempts: Int = 100,
    sleepNanoseconds: UInt64 = 5_000_000
) async -> Bool {
    for _ in 0..<maxAttempts {
        switch await dynamicForwardPostScopeAttemptOutcome(to: endpoint) {
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

private func dynamicForwardPostScopeAttemptOutcome(
    to endpoint: SSHSocketEndpoint
) async -> DynamicForwardPostScopeAttemptOutcome {
    await withTaskGroup(of: DynamicForwardPostScopeAttemptOutcome.self) { group in
        group.addTask {
            do {
                return try await dynamicForwardReceiveChunkOutcome(from: endpoint)
            } catch {
                return .refused
            }
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: 500_000_000)
            return .timedOut
        }

        guard let outcome = await group.next() else {
            fatalError("dynamic forward connection attempt returned no outcome")
        }

        group.cancelAll()
        return outcome
    }
}

private func dynamicForwardReceiveChunkOutcome(
    from endpoint: SSHSocketEndpoint
) async throws -> DynamicForwardPostScopeAttemptOutcome {
    try await SSHTCPByteStreamTransportFactory.withConnected(to: endpoint) { transport in
        let chunk = try await transport.receive(atLeast: 1, atMost: 4096)
        if chunk.endOfStream && chunk.bytes.isEmpty {
            return .closed
        }
        return .receivedData(chunk.bytes)
    }
}
