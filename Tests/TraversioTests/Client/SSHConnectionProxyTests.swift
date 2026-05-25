// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

actor ScriptedProxyHandshakeTransport: SSHByteStreamTransport {
    private let sshTransport: any SSHByteStreamTransport
    private let proxyResponsesBySend: [[UInt8]]
    private var queuedResponses: [SSHByteStreamChunk] = []
    private var sentPayloads: [[UInt8]] = []
    private var sendCount = 0
    private var closeCount = 0

    init(
        proxyResponsesBySend: [[UInt8]],
        sshTransport: any SSHByteStreamTransport
    ) {
        self.proxyResponsesBySend = proxyResponsesBySend
        self.sshTransport = sshTransport
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        self.sentPayloads.append(bytes)

        if self.sendCount < self.proxyResponsesBySend.count {
            self.queuedResponses.append(
                SSHByteStreamChunk(
                    bytes: self.proxyResponsesBySend[self.sendCount],
                    endOfStream: false
                )
            )
            self.sendCount += 1
            return
        }

        try await self.sshTransport.send(bytes, endOfStream: endOfStream)
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        if !self.queuedResponses.isEmpty {
            return self.queuedResponses.removeFirst()
        }

        return try await self.sshTransport.receive(atLeast: minimum, atMost: maximum)
    }

    func recordedSentPayloads() -> [[UInt8]] {
        self.sentPayloads
    }

    func closeCountObserved() -> Int {
        self.closeCount
    }

    func close() async {
        self.closeCount += 1
        await self.sshTransport.close()
    }
}

actor TransportFactoryCallRecorder {
    private var count = 0

    func record() {
        self.count += 1
    }

    func recordedCount() -> Int {
        self.count
    }
}

actor ProxyJumpConnectionRecorder {
    private var endpoints: [SSHSocketEndpoint] = []
    private var upstreamHosts: [String] = []

    func record(endpoint: SSHSocketEndpoint, upstreamConnection: SSHConnection) {
        self.endpoints.append(endpoint)
        self.upstreamHosts.append(upstreamConnection.metadata.endpointHost)
    }

    func recordedEndpoints() -> [SSHSocketEndpoint] {
        self.endpoints
    }

    func recordedUpstreamHosts() -> [String] {
        self.upstreamHosts
    }
}

@Test
func sshClientConfigurationDefaultsToNoConnectionProxy() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.connectionProxy == nil)
}

@Test
func sshClientConfigurationStoresConnectionProxy() {
    let proxy = SSHConnectionProxy.socks5(
        SSHSOCKS5ConnectionProxy(
            host: "proxy.example.com",
            port: 1080,
            authentication: .usernamePassword(username: "alice", password: "p@ss")
        )
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: proxy
    )

    #expect(configuration.connectionProxy == proxy)
}

@Test
func sshClientConnectsThroughSOCKS5ConnectionProxy() async throws {
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            [0x05, 0x00],
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        ],
        sshTransport: try makeAuthenticatedConnectionFixtureTransport()
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .socks5(
            SSHSOCKS5ConnectionProxy(host: "proxy.example.com")
        )
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 1080))
            return proxyTransport
        }
    )

    #expect(connection.metadata.endpointHost == "example.com")
    await connection.close()

    let sentPayloads = await proxyTransport.recordedSentPayloads()
    #expect(sentPayloads[0] == [0x05, 0x01, 0x00])
    #expect(
        sentPayloads[1] == makeSOCKS5DomainConnectRequest(
            host: "example.com",
            port: 22
        )
    )
}

@Test
func sshClientConnectsThroughSOCKS5ConnectionProxyWithUsernamePassword() async throws {
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            [0x05, 0x02],
            [0x01, 0x00],
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        ],
        sshTransport: try makeAuthenticatedConnectionFixtureTransport()
    )
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .socks5(
            SSHSOCKS5ConnectionProxy(
                host: "proxy.example.com",
                authentication: .usernamePassword(
                    username: "alice",
                    password: "p@ss"
                )
            )
        )
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 1080))
            return proxyTransport
        }
    )

    await connection.close()

    let sentPayloads = await proxyTransport.recordedSentPayloads()
    #expect(sentPayloads[0] == [0x05, 0x01, 0x02])
    #expect(sentPayloads[1] == [0x01, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x04, 0x70, 0x40, 0x73, 0x73])
    #expect(
        sentPayloads[2] == makeSOCKS5DomainConnectRequest(
            host: "db.internal",
            port: 22
        )
    )
}

@Test
func sshClientConnectsThroughHTTPConnectProxy() async throws {
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            Array("HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n".utf8),
        ],
        sshTransport: try makeAuthenticatedConnectionFixtureTransport()
    )
    let configuration = SSHClientConfiguration(
        host: "ssh.internal",
        port: 2222,
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .httpConnect(
            SSHHTTPConnectConnectionProxy(
                host: "proxy.example.com",
                port: 3128,
                authentication: .basic(username: "alice", password: "p@ss")
            )
        )
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 3128))
            return proxyTransport
        }
    )

    await connection.close()

    let expectedToken = Data("alice:p@ss".utf8).base64EncodedString()
    let sentPayloads = await proxyTransport.recordedSentPayloads()
    #expect(
        sentPayloads[0] == Array(
            (
                "CONNECT ssh.internal:2222 HTTP/1.1\r\n" +
                "Host: ssh.internal:2222\r\n" +
                "Proxy-Authorization: Basic \(expectedToken)\r\n" +
                "\r\n"
            )
                .utf8
        )
    )
}

@Test
func sshClientClosesConnectionProxyTransportAfterHandshakeFailure() async throws {
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            Array("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".utf8),
        ],
        sshTransport: try makeAuthenticatedConnectionFixtureTransport()
    )
    let configuration = SSHClientConfiguration(
        host: "ssh.internal",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .httpConnect(
            SSHHTTPConnectConnectionProxy(host: "proxy.example.com", port: 3128)
        )
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in proxyTransport }
        )
        Issue.record("Expected HTTP CONNECT proxy rejection to fail connection setup")
    } catch {
        guard case let SSHClientError.connectionFailed(failure) = error else {
            Issue.record("Expected public connection failure, got \(error)")
            return
        }
        #expect(failure.stage == .transport)
        #expect(failure.code == .transportError)
        #expect(failure.message.contains("HTTP CONNECT proxy returned status 502"))
    }

    #expect(await proxyTransport.closeCountObserved() == 1)
}

@Test
func sshClientRejectsInvalidSOCKS5ConnectionProxyCredentialsBeforeConnecting() async throws {
    let recorder = TransportFactoryCallRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .socks5(
            SSHSOCKS5ConnectionProxy(
                host: "proxy.example.com",
                authentication: .usernamePassword(username: "", password: "secret")
            )
        )
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { endpoint in
                _ = endpoint
                await recorder.record()
                return try makeAuthenticatedConnectionFixtureTransport()
            }
        )
        Issue.record("Expected the invalid proxy configuration to fail.")
    } catch {
        #expect(error is SSHClientError)
    }

    #expect(await recorder.recordedCount() == 0)
}

@Test
func sshClientAppliesConnectionProxyOnlyToTheOutermostProxyJumpHop() async throws {
    let firstHopProxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
        ],
        sshTransport: try makeAuthenticatedConnectionFixtureTransport()
    )
    let finalTransport = try makeAuthenticatedConnectionFixtureTransport()
    let recorder = ProxyJumpConnectionRecorder()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        connectionProxy: .httpConnect(
            SSHHTTPConnectConnectionProxy(host: "proxy.example.com", port: 3128)
        ),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump",
                authentication: .password("jump-secret"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 3128))
            return firstHopProxyTransport
        },
        jumpTransportFactory: { upstreamConnection, endpoint in
            await recorder.record(endpoint: endpoint, upstreamConnection: upstreamConnection)
            return SSHClientTransportHandle(transport: finalTransport)
        }
    )

    await connection.close()

    let firstHopPayloads = await firstHopProxyTransport.recordedSentPayloads()
    let firstHopRequest = firstHopPayloads[0]
    #expect(
        firstHopRequest
            == Array(
                (
                    "CONNECT jump-1.example.com:22 HTTP/1.1\r\n" +
                    "Host: jump-1.example.com:22\r\n" +
                    "\r\n"
                )
                    .utf8
            )
    )
    #expect(await recorder.recordedEndpoints() == [SSHSocketEndpoint(host: "db.internal", port: 22)])
    #expect(await recorder.recordedUpstreamHosts() == ["jump-1.example.com"])
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

private func makeSOCKS5DomainConnectRequest(
    host: String,
    port: UInt16
) -> [UInt8] {
    let hostBytes = Array(host.utf8)
    return [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)] +
        hostBytes +
        [UInt8(port >> 8), UInt8(port & 0xff)]
}
