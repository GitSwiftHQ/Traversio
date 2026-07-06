// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Darwin
import Foundation
import Network
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
func tcpListenerBindHostNormalizesLocalhostToNumericLoopback() {
    #expect(SSHTCPEndpointParser.listenerBindHost("localhost") == .ipv4(.loopback))
    #expect(SSHTCPEndpointParser.listenerBindHost("LocalHost") == .ipv4(.loopback))
    #expect(
        SSHTCPEndpointParser.listenerBindHost("127.0.0.1")
            == NWEndpoint.Host("127.0.0.1")
    )
    #expect(SSHTCPEndpointParser.listenerBindHost("::1") == NWEndpoint.Host("::1"))
    #expect(
        SSHTCPEndpointParser.listenerBindHost("example.test")
            == NWEndpoint.Host("example.test")
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpListenerLegacyLocalhostFixedPortBindsRequestedPort() async throws {
    try await expectLocalhostFixedPortListenerBindsRequestedPort(preference: .legacy)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func tcpListenerModernLocalhostFixedPortBindsRequestedPort() async throws {
    guard SSHTCPTransportFlowPolicy.isModernNetworkConnectionAvailable else {
        return
    }

    try await expectLocalhostFixedPortListenerBindsRequestedPort(preference: .modern)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func expectLocalhostFixedPortListenerBindsRequestedPort(
    preference: SSHTCPTransportBackendPreference
) async throws {
    var lastAddressInUseError: (any Error)?

    for _ in 0..<10 {
        do {
            try await expectLocalhostFixedPortListenerBindsRequestedPortOnce(preference: preference)
            return
        } catch {
            guard isAddressInUse(error) else {
                throw error
            }
            lastAddressInUseError = error
        }
    }

    throw lastAddressInUseError ?? POSIXError(.EADDRINUSE)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func expectLocalhostFixedPortListenerBindsRequestedPortOnce(
    preference: SSHTCPTransportBackendPreference
) async throws {
    // A `localhost` bind previously produced a name-based required local
    // endpoint, which Network.framework listeners cannot bind: the requested
    // fixed port was silently ignored and an assigned port was bound instead.
    let fixedPort = try allocateUnusedLoopbackPort()
    let listener = try SSHTCPListenerFactory.makeListener(
        localHost: "localhost",
        localPort: fixedPort,
        preference: preference
    )
    let probe = TCPListenerProbe()
    let listenerTask = Task {
        try await listener.run { acceptedConnection in
            await probe.handle(acceptedConnection)
        }
    }

    do {
        let readyPort = try await listener.readyPort()
        #expect(readyPort == fixedPort)

        let response = try await LegacyNetworkTCPByteStreamTransport.withConnected(
            to: SSHSocketEndpoint(host: "127.0.0.1", port: fixedPort)
        ) { transport in
            try await transport.send(Array("PING".utf8), endOfStream: false)
            return try await readExactByteCount(4, from: transport)
        }

        #expect(response == Array("PONG".utf8))
        #expect(try await probe.receivedBytes() == Array("PING".utf8))
    } catch {
        listenerTask.cancel()
        _ = try? await listenerTask.value
        throw error
    }

    listenerTask.cancel()
    _ = try? await listenerTask.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func allocateUnusedLoopbackPort() throws -> UInt16 {
    let socketDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socketDescriptor >= 0 else {
        throw currentPOSIXError()
    }
    defer {
        Darwin.close(socketDescriptor)
    }

    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = in_port_t(0).bigEndian
    address.sin_addr = in_addr(s_addr: UInt32(0x7f00_0001).bigEndian)

    let bindResult = withUnsafePointer(to: &address) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.bind(
                socketDescriptor,
                socketAddress,
                socklen_t(MemoryLayout<sockaddr_in>.size)
            )
        }
    }
    guard bindResult == 0 else {
        throw currentPOSIXError()
    }

    var boundAddress = sockaddr_in()
    var boundAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameResult = withUnsafeMutablePointer(to: &boundAddress) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.getsockname(socketDescriptor, socketAddress, &boundAddressLength)
        }
    }
    guard nameResult == 0 else {
        throw currentPOSIXError()
    }

    let assignedPort = UInt16(bigEndian: boundAddress.sin_port)
    guard assignedPort != 0 else {
        throw POSIXError(.EINVAL)
    }
    return assignedPort
}

private func currentPOSIXError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EINVAL)
}

private func isAddressInUse(_ error: any Error) -> Bool {
    if let posixError = error as? POSIXError {
        return posixError.code == .EADDRINUSE
    }

    if let networkError = error as? NWError,
       case let .posix(code) = networkError {
        return code == .EADDRINUSE
    }

    return false
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
