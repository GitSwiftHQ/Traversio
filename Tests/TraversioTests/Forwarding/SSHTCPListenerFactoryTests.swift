// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpListenerFactoryLifecycleControlledAutomaticUsesLegacyListener() throws {
    let listener = try SSHTCPListenerFactory.makeLifecycleControlledListener(
        localHost: "127.0.0.1",
        localPort: 0,
        preference: .automatic
    )

    #expect(listener is LegacyNetworkTCPListener)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpListenerFactoryLegacyPreferenceAcceptsLoopbackConnection() async throws {
    let listener = try SSHTCPListenerFactory.makeListener(
        localHost: "127.0.0.1",
        localPort: 0,
        preference: .legacy
    )
    let probe = TCPListenerProbe()
    let listenerTask = Task {
        try await listener.run { acceptedConnection in
            await probe.handle(acceptedConnection)
        }
    }

    let endpoint = SSHSocketEndpoint(
        host: "127.0.0.1",
        port: try await listener.readyPort()
    )

    let response = try await LegacyNetworkTCPByteStreamTransport.withConnected(
        to: endpoint
    ) { transport in
        try await transport.send(Array("PING".utf8), endOfStream: false)
        return try await readExactByteCount(4, from: transport)
    }

    listenerTask.cancel()
    _ = try? await listenerTask.value

    #expect(response == Array("PONG".utf8))
    #expect(try await probe.receivedBytes() == Array("PING".utf8))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpAsyncResultWaiterCancellationDoesNotPoisonStoredResult() async throws {
    let result = SSHTCPAsyncResult<Int>()
    let cancelledTask = Task {
        try await result.value()
    }

    await Task.yield()
    cancelledTask.cancel()

    do {
        _ = try await cancelledTask.value
        Issue.record("Expected cancelled result waiter to throw CancellationError")
    } catch is CancellationError {
    } catch {
        Issue.record("Expected CancellationError, got \(String(reflecting: error))")
    }

    #expect(result.resume(with: .success(42)))
    #expect(try await result.value() == 42)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private actor TCPListenerProbe {
    private let receivedState = SSHTCPAsyncResult<[UInt8]>()

    func handle(_ acceptedConnection: SSHTCPAcceptedConnection) async {
        do {
            let bytes = try await readExactByteCount(4, from: acceptedConnection.transport)
            self.receivedState.resume(with: .success(bytes))
            try await acceptedConnection.transport.send(Array("PONG".utf8), endOfStream: true)
        } catch {
            self.receivedState.resume(with: .failure(error))
        }
    }

    func receivedBytes() async throws -> [UInt8] {
        try await self.receivedState.value()
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
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
