// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
package struct NetworkTCPByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    private static let operationCanceledPOSIXCode = POSIXErrorCode(rawValue: 89)
    private static let operationCanceledPOSIXRawValue = 89

    // Safety invariant:
    // `withNetworkConnection` in the Xcode 26.3 SDK only accepts a `Void`-returning async handler.
    // This box is written exactly once from that handler before the helper returns, and is read only
    // after `withNetworkConnection` has completed on the caller task.
    private final class ResultBox<Result>: @unchecked Sendable {
        var value: Result?

        func store(_ value: Result) {
            precondition(self.value == nil, "withConnected result stored more than once")
            self.value = value
        }
    }

    package final class CloseState: @unchecked Sendable {
        private let lock = NSLock()
        private var didClaimEndOfStream = false

        package init() {
        }

        package func claimEndOfStreamSend() -> Bool {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didClaimEndOfStream else {
                return false
            }

            self.didClaimEndOfStream = true
            return true
        }
    }

    private final class ConnectionBox: @unchecked Sendable {
        // Sendable invariant: every mutable field is accessed only while `lock` is held.
        private let lock = NSLock()
        private var connection: NetworkConnection<TCP>?
        private var observationHandler: (@Sendable (SSHTransportObservationEvent) -> Void)?
        private var didInstallObservationHandlers = false
        private var isClosed = false

        init(connection: NetworkConnection<TCP>) {
            self.connection = connection
        }

        func connectionSnapshot() throws -> NetworkConnection<TCP> {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.isClosed, let connection = self.connection else {
                throw SSHTransportError.transportClosed
            }
            return connection
        }

        func updateObservationHandler(
            _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
        ) -> NetworkConnection<TCP>? {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.isClosed, let connection = self.connection else {
                self.observationHandler = nil
                return nil
            }

            self.observationHandler = handler
            guard handler != nil, !self.didInstallObservationHandlers else {
                return nil
            }

            self.didInstallObservationHandlers = true
            return connection
        }

        func emit(_ event: SSHTransportObservationEvent) {
            self.lock.lock()
            let handler = self.observationHandler
            self.lock.unlock()

            handler?(event)
        }

        func close() -> NetworkConnection<TCP>? {
            self.lock.lock()
            let connection = self.connection
            self.isClosed = true
            self.connection = nil
            self.observationHandler = nil
            self.lock.unlock()
            return connection
        }
    }

    private let connectionBox: ConnectionBox
    private let closeState = CloseState()

    package init(connection: NetworkConnection<TCP>) {
        self.connectionBox = ConnectionBox(connection: connection)
    }

    package func send(_ bytes: [UInt8], endOfStream: Bool = false) async throws {
        try await self.send(bytes, endOfStream: endOfStream, respectCancellation: true)
    }

    package func send(
        _ bytes: [UInt8],
        endOfStream: Bool = false,
        respectCancellation: Bool
    ) async throws {
        if respectCancellation {
            try Task.checkCancellation()
            let connection = try self.connectionBox.connectionSnapshot()
            if endOfStream {
                guard self.closeState.claimEndOfStreamSend() else {
                    return
                }
            }
            try await connection.send(bytes, endOfStream: endOfStream)
            return
        }

        let connection = try self.connectionBox.connectionSnapshot()
        if endOfStream {
            guard self.closeState.claimEndOfStreamSend() else {
                return
            }
        }
        try await Self.performIgnoringCallerCancellation {
            try await connection.send(bytes, endOfStream: endOfStream)
        }
    }

    package func receive(atLeast minimum: Int = 1, atMost maximum: Int = 4096) async throws -> SSHByteStreamChunk {
        try await self.receive(
            atLeast: minimum,
            atMost: maximum,
            respectCancellation: true
        )
    }

    package func receive(
        atLeast minimum: Int = 1,
        atMost maximum: Int = 4096,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        if respectCancellation {
            try Task.checkCancellation()
        }
        if respectCancellation {
            let connection = try self.connectionBox.connectionSnapshot()
            let message = try await connection.receive(atLeast: minimum, atMost: maximum)
            let bytes = Array(message.content)

            guard !bytes.isEmpty || message.metadata.endOfStream else {
                throw SSHTransportError.emptyReceive
            }

            return SSHByteStreamChunk(bytes: bytes, endOfStream: message.metadata.endOfStream)
        }

        let connection = try self.connectionBox.connectionSnapshot()
        return try await Self.performIgnoringCallerCancellation {
            let message = try await connection.receive(atLeast: minimum, atMost: maximum)
            let bytes = Array(message.content)

            guard !bytes.isEmpty || message.metadata.endOfStream else {
                throw SSHTransportError.emptyReceive
            }

            return SSHByteStreamChunk(bytes: bytes, endOfStream: message.metadata.endOfStream)
        }
    }

    private static func performIgnoringCallerCancellation<Result: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        let task = Task {
            try await operation()
        }
        return try await task.value
    }

    package func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async {
        let box = self.connectionBox
        guard let connection = box.updateObservationHandler(handler) else {
            return
        }

        connection
            .onStateUpdate { _, state in
                box.emit(
                    .stateChanged(
                        state: Self.transportObservedState(from: state),
                        detail: Self.transportObservedStateDetail(from: state)
                    )
                )
            }
            .onPathUpdate { _, newPath in
                box.emit(.networkPathChanged(Self.transportNetworkPath(from: newPath)))
            }
            .onViabilityUpdate { _, newIsViable in
                box.emit(.viabilityChanged(newIsViable))
            }
            .onBetterPathUpdate { _, newValue in
                box.emit(.betterPathAvailable(newValue))
            }
    }

    package func close() async {
        _ = self.connectionBox.close()
    }

    package func abort() async {
        await self.close()
    }

    package static func connect(
        to endpoint: SSHSocketEndpoint
    ) throws -> NetworkTCPByteStreamTransport {
        let remoteEndpoint = try self.remoteEndpoint(for: endpoint)
        let connection = NetworkConnection(to: remoteEndpoint, using: { TCP() })
        return NetworkTCPByteStreamTransport(connection: connection)
    }

    package static func withConnected<Result>(
        to endpoint: SSHSocketEndpoint,
        _ body: (NetworkTCPByteStreamTransport) async throws -> Result
    ) async throws -> Result {
        let remoteEndpoint = try self.remoteEndpoint(for: endpoint)

        try Task.checkCancellation()
        let resultBox = ResultBox<Result>()

        do {
            try await withNetworkConnection(to: remoteEndpoint, using: { TCP() }) { connection in
                try Task.checkCancellation()
                resultBox.store(
                    try await body(NetworkTCPByteStreamTransport(connection: connection))
                )
            }
        } catch {
            if let result = resultBox.value,
               self.isExpectedScopedCloseError(error) {
                return result
            }
            throw error
        }

        return try self.requireScopedResult(
            resultBox.value,
            endpoint: endpoint
        )
    }

    private static func remoteEndpoint(for endpoint: SSHSocketEndpoint) throws -> NWEndpoint {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw SSHTransportError.invalidPort(endpoint.port)
        }

        return NWEndpoint.hostPort(
            host: NWEndpoint.Host(endpoint.host),
            port: port
        )
    }

    package static func requireScopedResult<Result>(
        _ result: Result?,
        endpoint: SSHSocketEndpoint
    ) throws -> Result {
        guard let result else {
            throw SSHTransportError.internalInvariantBroken(
                "withNetworkConnection completed without producing a result for \(endpoint.host):\(endpoint.port)"
            )
        }
        return result
    }

    package static func isExpectedScopedCloseError(_ error: any Error) -> Bool {
        if let networkError = error as? NWError,
           case let .posix(code) = networkError,
           code == self.operationCanceledPOSIXCode {
            return true
        }
        if let posixError = error as? POSIXError,
           posixError.code == self.operationCanceledPOSIXCode {
            return true
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain,
           nsError.code == self.operationCanceledPOSIXRawValue {
            return true
        }
        return false
    }

    private static func transportObservedState(
        from state: NetworkChannel<TCP>.State
    ) -> SSHTransportObservedState {
        switch state {
        case .setup:
            return .setup
        case .waiting:
            return .waiting
        case .preparing:
            return .preparing
        case .ready:
            return .ready
        case .failed:
            return .failed
        case .cancelled:
            return .cancelled
        @unknown default:
            return .failed
        }
    }

    private static func transportObservedStateDetail(
        from state: NetworkChannel<TCP>.State
    ) -> String? {
        switch state {
        case let .waiting(error), let .failed(error):
            return String(reflecting: error)
        case .setup, .preparing, .ready, .cancelled:
            return nil
        @unknown default:
            return nil
        }
    }

    private static func transportNetworkPath(
        from path: NWPath
    ) -> SSHTransportNetworkPath {
        SSHTransportNetworkPath(
            status: self.transportNetworkPathStatus(from: path.status),
            availableInterfaces: path.availableInterfaces.map(self.transportNetworkInterface),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6
        )
    }

    private static func transportNetworkPathStatus(
        from status: NWPath.Status
    ) -> SSHTransportNetworkPathStatus {
        switch status {
        case .satisfied:
            return .satisfied
        case .unsatisfied:
            return .unsatisfied
        case .requiresConnection:
            return .requiresConnection
        @unknown default:
            return .unsatisfied
        }
    }

    private static func transportNetworkInterface(
        _ interface: NWInterface
    ) -> SSHTransportNetworkInterface {
        switch interface.type {
        case .wifi:
            return .wifi
        case .cellular:
            return .cellular
        case .wiredEthernet:
            return .wiredEthernet
        case .loopback:
            return .loopback
        case .other:
            return .other
        @unknown default:
            return .other
        }
    }
}
