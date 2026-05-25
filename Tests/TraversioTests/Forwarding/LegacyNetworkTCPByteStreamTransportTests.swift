// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch
import Foundation
import Network
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func legacyNetworkTCPByteStreamTransportRoundTripsStreamData() async throws {
    let server = try await LegacyTransportTestServer.start(response: Array("pong".utf8))
    defer {
        server.stop()
    }

    let transport = try await LegacyNetworkTCPByteStreamTransport.connect(
        to: SSHSocketEndpoint(host: "127.0.0.1", port: server.port)
    )

    try await transport.send(Array("ping".utf8), endOfStream: false)

    let reply = try await collectBytesUntilEndOfStream(from: transport)
    #expect(reply == Array("pong".utf8))
    #expect(try await server.receivedBytes() == Array("ping".utf8))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpByteStreamTransportFactoryRoundTripsStreamData() async throws {
    let server = try await LegacyTransportTestServer.start(response: Array("pong".utf8))
    defer {
        server.stop()
    }

    let transport = try await SSHTCPByteStreamTransportFactory.connect(
        to: SSHSocketEndpoint(host: "127.0.0.1", port: server.port)
    )

    try await transport.send(Array("ping".utf8), endOfStream: false)

    let reply = try await collectBytesUntilEndOfStream(from: transport)
    #expect(reply == Array("pong".utf8))
    #expect(try await server.receivedBytes() == Array("ping".utf8))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpByteStreamTransportFactoryLegacyPreferenceRoundTripsStreamData() async throws {
    let server = try await LegacyTransportTestServer.start(response: Array("pong".utf8))
    defer {
        server.stop()
    }

    let reply = try await SSHTCPByteStreamTransportFactory.withConnected(
        to: SSHSocketEndpoint(host: "127.0.0.1", port: server.port),
        preference: .legacy
    ) { transport in
        try await transport.send(Array("ping".utf8), endOfStream: false)
        return try await collectBytesUntilEndOfStream(from: transport)
    }

    #expect(reply == Array("pong".utf8))
    #expect(try await server.receivedBytes() == Array("ping".utf8))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func collectBytesUntilEndOfStream(
    from transport: any SSHByteStreamTransport
) async throws -> [UInt8] {
    var bytes: [UInt8] = []

    while true {
        let chunk = try await transport.receive(atLeast: 1, atMost: 4096)
        bytes.append(contentsOf: chunk.bytes)

        if chunk.endOfStream {
            return bytes
        }
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private final class LegacyTransportTestServer: @unchecked Sendable {
    private(set) var port: UInt16

    private let listener: NWListener
    private let queue: DispatchQueue
    private let response: [UInt8]
    private let receivedState = OneShotValue<[UInt8]>()
    private let acceptedConnectionLock = NSLock()
    private var acceptedConnection: NWConnection?

    private init(listener: NWListener, response: [UInt8]) {
        self.listener = listener
        self.port = 0
        self.response = response
        self.queue = DispatchQueue(
            label: "Traversio.LegacyTransportTestServer.\(UUID().uuidString)"
        )
    }

    static func start(response: [UInt8]) async throws -> LegacyTransportTestServer {
        let listener = try NWListener(using: .tcp, on: .any)
        let readyState = OneShotValue<UInt16>()
        let server = LegacyTransportTestServer(listener: listener, response: response)

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port?.rawValue {
                    readyState.resume(with: .success(port))
                }
            case let .failed(error):
                readyState.resume(with: .failure(error))
            case .cancelled:
                readyState.resume(with: .failure(CancellationError()))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }

        listener.newConnectionHandler = { [server, queue = server.queue, response = response, receivedState = server.receivedState] connection in
            server.storeAcceptedConnection(connection)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) {
                        content,
                        _,
                        _,
                        error in
                        if let error {
                            receivedState.resume(with: .failure(error))
                            connection.cancel()
                            return
                        }

                        receivedState.resume(with: .success(Array(content ?? Data())))

                        connection.send(
                            content: Data(response),
                            contentContext: .defaultStream,
                            isComplete: true,
                            completion: .contentProcessed { _ in }
                        )
                    }
                case let .failed(error):
                    receivedState.resume(with: .failure(error))
                case .cancelled, .setup, .waiting, .preparing:
                    break
                @unknown default:
                    break
                }
            }

            connection.start(queue: queue)
        }

        listener.start(queue: server.queue)
        server.port = try await readyState.value()
        return server
    }

    func receivedBytes() async throws -> [UInt8] {
        try await self.receivedState.value()
    }

    func stop() {
        self.acceptedConnectionLock.lock()
        let acceptedConnection = self.acceptedConnection
        self.acceptedConnection = nil
        self.acceptedConnectionLock.unlock()

        acceptedConnection?.stateUpdateHandler = nil
        acceptedConnection?.cancel()
        self.listener.stateUpdateHandler = nil
        self.listener.newConnectionHandler = nil
        self.listener.cancel()
    }

    private func storeAcceptedConnection(_ connection: NWConnection) {
        self.acceptedConnectionLock.lock()
        self.acceptedConnection = connection
        self.acceptedConnectionLock.unlock()
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private final class OneShotValue<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var result: Result<Value, Error>?
    private var didResume = false

    func value() async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            self.install(continuation)
        }
    }

    func install(_ continuation: CheckedContinuation<Value, Error>) {
        let result: Result<Value, Error>?

        self.lock.lock()
        if self.didResume {
            result = self.result
        } else {
            self.continuation = continuation
            result = nil
        }
        self.lock.unlock()

        guard let result else {
            return
        }

        continuation.resume(with: result)
    }

    @discardableResult
    func resume(with result: Result<Value, Error>) -> Bool {
        let continuation: CheckedContinuation<Value, Error>?

        self.lock.lock()
        guard !self.didResume else {
            self.lock.unlock()
            return false
        }

        self.didResume = true
        self.result = result
        continuation = self.continuation
        self.continuation = nil
        self.lock.unlock()

        continuation?.resume(with: result)
        return true
    }
}
