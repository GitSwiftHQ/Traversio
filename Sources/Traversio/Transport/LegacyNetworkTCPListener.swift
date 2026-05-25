// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch
import Foundation
import Network
package final class LegacyNetworkTCPListener: @unchecked Sendable, SSHTCPListener {
    // Sendable invariant: start/cancel state is protected by `stateLock`; listener callbacks run
    // on `queue`; readiness and terminal completion are protected by `SSHTCPAsyncResult`;
    // cancellation and handler cleanup are protected by `stateLock`.
    private let listener: NWListener
    private let queue: DispatchQueue
    private let readyState = SSHTCPAsyncResult<UInt16>()
    private let terminalState = SSHTCPAsyncResult<Void>()
    private let stateLock = NSLock()
    private var didStart = false
    private var didCancel = false

    package init(localHost: String, localPort: UInt16) throws {
        let listener = try NWListener(
            using: SSHTCPListenerFactory.listenerParameters(
                localHost: localHost,
                localPort: localPort
            ),
            on: .any
        )
        self.listener = listener
        self.queue = DispatchQueue(
            label: "Traversio.LegacyNetworkTCPListener.\(UUID().uuidString)"
        )

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let boundPort = listener.port?.rawValue {
                    self.readyState.resume(with: .success(boundPort))
                } else {
                    let error = SSHTransportError.listenerDidNotReportPort
                    self.readyState.resume(with: .failure(error))
                    self.terminalState.resume(with: .failure(error))
                }
            case let .failed(error):
                self.readyState.resume(with: .failure(error))
                self.terminalState.resume(with: .failure(error))
            case .cancelled:
                let error = CancellationError()
                self.readyState.resume(with: .failure(error))
                self.terminalState.resume(with: .failure(error))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
    }

    deinit {
        self.cancelIfNeeded()
    }

    package func readyPort() async throws -> UInt16 {
        try await self.readyState.value()
    }

    package func run(
        _ handler: @escaping @Sendable (SSHTCPAcceptedConnection) async -> Void
    ) async throws {
        guard self.installNewConnectionHandler({ connection in
            let connectionQueue = DispatchQueue(
                label: "Traversio.LegacyNetworkTCPListener.Accepted.\(UUID().uuidString)"
            )
            connection.start(queue: connectionQueue)

            let acceptedConnection = SSHTCPAcceptedConnection(
                originatorResult: SSHTCPEndpointParser.originatorResult(
                    for: connection.endpoint
                ),
                transport: LegacyNetworkTCPByteStreamTransport.adoptAcceptedConnection(
                    connection,
                    queue: connectionQueue
                )
            )

            Task {
                await handler(acceptedConnection)
            }
        }) else {
            throw CancellationError()
        }

        try await withTaskCancellationHandler {
            guard self.startIfNeeded() else {
                throw CancellationError()
            }
            _ = try await self.terminalState.value()
        } onCancel: {
            self.cancelIfNeeded()
        }
    }

    private func installNewConnectionHandler(
        _ handler: @escaping @Sendable (NWConnection) -> Void
    ) -> Bool {
        self.stateLock.lock()
        defer { self.stateLock.unlock() }

        guard !self.didCancel else {
            return false
        }

        self.listener.newConnectionHandler = handler
        return true
    }

    private func startIfNeeded() -> Bool {
        self.stateLock.lock()
        defer { self.stateLock.unlock() }

        guard !self.didCancel else {
            return false
        }
        guard !self.didStart else {
            return true
        }

        self.didStart = true
        self.listener.start(queue: self.queue)
        return true
    }

    private func cancelIfNeeded() {
        self.stateLock.lock()
        defer { self.stateLock.unlock() }

        guard !self.didCancel else {
            return
        }

        self.didCancel = true
        let cancellation = CancellationError()
        self.readyState.resume(with: .failure(cancellation))
        self.terminalState.resume(with: .failure(cancellation))
        self.listener.stateUpdateHandler = nil
        self.listener.newConnectionHandler = nil
        self.listener.cancel()
    }
}
