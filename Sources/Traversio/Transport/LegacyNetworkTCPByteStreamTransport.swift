// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch
import Foundation
import Network
package actor LegacyNetworkTCPByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    private final class ConnectionBox: @unchecked Sendable {
        // Sendable invariant: `NWConnection` callback mutation, start, and cancel
        // are serialized by `lock` so no caller mutates handlers after cancel.
        private let lock = NSLock()
        private var didCancel = false
        let connection: NWConnection
        let queue: DispatchQueue

        init(connection: NWConnection, queue: DispatchQueue) {
            self.connection = connection
            self.queue = queue
        }

        deinit {
            self.cancel()
        }

        @discardableResult
        func setStartupStateUpdateHandler(
            _ handler: @escaping @Sendable (NWConnection.State) -> Void
        ) -> Bool {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didCancel else {
                return false
            }

            self.connection.stateUpdateHandler = handler
            return true
        }

        @discardableResult
        func start() -> Bool {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didCancel else {
                return false
            }

            self.connection.start(queue: self.queue)
            return true
        }

        func clearStateUpdateHandlerIfActive() {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didCancel else {
                return
            }

            self.connection.stateUpdateHandler = nil
        }

        func setObservationHandlers(
            state: (@Sendable (NWConnection.State) -> Void)?,
            path: (@Sendable (NWPath) -> Void)?,
            viability: (@Sendable (Bool) -> Void)?,
            betterPath: (@Sendable (Bool) -> Void)?
        ) {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didCancel else {
                return
            }

            self.connection.stateUpdateHandler = state
            self.connection.pathUpdateHandler = path
            self.connection.viabilityUpdateHandler = viability
            self.connection.betterPathUpdateHandler = betterPath
        }

        func cancel() {
            self.lock.lock()
            defer { self.lock.unlock() }

            guard !self.didCancel else {
                return
            }

            self.didCancel = true
            self.connection.stateUpdateHandler = nil
            self.connection.pathUpdateHandler = nil
            self.connection.viabilityUpdateHandler = nil
            self.connection.betterPathUpdateHandler = nil
            self.connection.cancel()
        }
    }

    private final class CompletionState<Value: Sendable>: @unchecked Sendable {
        // Sendable invariant: continuation, result, and resume state are protected by `lock`.
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Value, Error>?
        private var result: Result<Value, Error>?
        private var didResume = false

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

            switch result {
            case let .success(value):
                continuation?.resume(returning: value)
            case let .failure(error):
                continuation?.resume(throwing: error)
            }
            return true
        }
    }

    private let box: ConnectionBox
    private var observationHandler: (@Sendable (SSHTransportObservationEvent) -> Void)?

    private init(box: ConnectionBox) {
        self.box = box
    }

    package static func adoptAcceptedConnection(
        _ connection: NWConnection,
        queue: DispatchQueue
    ) -> LegacyNetworkTCPByteStreamTransport {
        LegacyNetworkTCPByteStreamTransport(
            box: ConnectionBox(connection: connection, queue: queue)
        )
    }

    package static func connect(
        to endpoint: SSHSocketEndpoint
    ) async throws -> LegacyNetworkTCPByteStreamTransport {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw SSHTransportError.invalidPort(endpoint.port)
        }

        let connection = NWConnection(
            host: NWEndpoint.Host(endpoint.host),
            port: port,
            using: .tcp
        )
        let box = ConnectionBox(
            connection: connection,
            queue: DispatchQueue(
                label: "Traversio.LegacyNetworkTCPByteStreamTransport.\(UUID().uuidString)"
            )
        )

        try await self.waitUntilReady(box)
        return LegacyNetworkTCPByteStreamTransport(box: box)
    }

    package static func withConnected<Result>(
        to endpoint: SSHSocketEndpoint,
        _ body: @escaping @Sendable (LegacyNetworkTCPByteStreamTransport) async throws -> Result
    ) async throws -> Result {
        let transport = try await self.connect(to: endpoint)

        do {
            let result = try await body(transport)
            await transport.close()
            return result
        } catch {
            await transport.close()
            throw error
        }
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
        }

        guard !bytes.isEmpty || endOfStream else {
            return
        }

        let box = self.box
        let completionState = CompletionState<Void>()

        let operation = {
            try await withCheckedThrowingContinuation { continuation in
                completionState.install(continuation)

                box.connection.send(
                    content: bytes.isEmpty ? nil : Data(bytes),
                    contentContext: .defaultStream,
                    isComplete: endOfStream,
                    completion: .contentProcessed { error in
                        if let error {
                            completionState.resume(with: .failure(error))
                            return
                        }

                        completionState.resume(with: .success(()))
                    }
                )
            }
        }

        if respectCancellation {
            try await withTaskCancellationHandler {
                try await operation()
            } onCancel: {
                box.cancel()
                completionState.resume(with: .failure(CancellationError()))
            }
        } else {
            try await operation()
        }
    }

    package func receive(
        atLeast minimum: Int = 1,
        atMost maximum: Int = 4096
    ) async throws -> SSHByteStreamChunk {
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
        precondition(minimum > 0, "minimum receive size must be positive")
        precondition(maximum >= minimum, "maximum receive size must cover the minimum")

        if respectCancellation {
            try Task.checkCancellation()
        }

        let box = self.box
        let completionState = CompletionState<SSHByteStreamChunk>()

        let operation = {
            try await withCheckedThrowingContinuation { continuation in
                completionState.install(continuation)

                box.connection.receive(
                    minimumIncompleteLength: minimum,
                    maximumLength: maximum
                ) { content, _, isComplete, error in
                    if let error {
                        completionState.resume(with: .failure(error))
                        return
                    }

                    let bytes = Array(content ?? Data())
                    guard !bytes.isEmpty || isComplete else {
                        completionState.resume(
                            with: .failure(SSHTransportError.emptyReceive)
                        )
                        return
                    }

                    completionState.resume(
                        with: .success(
                            SSHByteStreamChunk(bytes: bytes, endOfStream: isComplete)
                        )
                    )
                }
            }
        }

        if respectCancellation {
            return try await withTaskCancellationHandler {
                try await operation()
            } onCancel: {
                box.cancel()
                completionState.resume(with: .failure(CancellationError()))
            }
        }

        return try await operation()
    }

    package func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async {
        self.observationHandler = handler
        let box = self.box
        let observationHandler = self.observationHandler

        guard let observationHandler else {
            box.setObservationHandlers(
                state: nil,
                path: nil,
                viability: nil,
                betterPath: nil
            )
            return
        }

        box.setObservationHandlers(
            state: { state in
                observationHandler(
                    .stateChanged(
                        state: Self.transportObservedState(from: state),
                        detail: Self.transportObservedStateDetail(from: state)
                    )
                )
            },
            path: { newPath in
                observationHandler(
                    .networkPathChanged(Self.transportNetworkPath(from: newPath))
                )
            },
            viability: { newIsViable in
                observationHandler(.viabilityChanged(newIsViable))
            },
            betterPath: { newValue in
                observationHandler(.betterPathAvailable(newValue))
            }
        )
    }

    package func close() async {
        self.box.cancel()
    }

    private static func waitUntilReady(_ box: ConnectionBox) async throws {
        let completionState = CompletionState<Void>()

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completionState.install(continuation)

                guard box.setStartupStateUpdateHandler({ state in
                    switch state {
                    case .ready:
                        box.clearStateUpdateHandlerIfActive()
                        completionState.resume(with: .success(()))
                    case let .failed(error):
                        box.clearStateUpdateHandlerIfActive()
                        completionState.resume(with: .failure(error))
                    case .cancelled:
                        completionState.resume(with: .failure(CancellationError()))
                    case .setup, .waiting, .preparing:
                        break
                    @unknown default:
                        break
                    }
                }) else {
                    completionState.resume(with: .failure(CancellationError()))
                    return
                }

                guard box.start() else {
                    completionState.resume(with: .failure(CancellationError()))
                    return
                }
            }
        } onCancel: {
            box.cancel()
            completionState.resume(with: .failure(CancellationError()))
        }
    }

    private static func transportObservedState(
        from state: NWConnection.State
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
        from state: NWConnection.State
    ) -> String? {
        switch state {
        case let .waiting(error), let .failed(error):
            return SSHConnectionStateErrorDescription.describe(error)
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
