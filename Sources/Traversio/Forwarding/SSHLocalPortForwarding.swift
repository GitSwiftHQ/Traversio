// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Active local port-forward listener details.
///
/// Returned from `SSHConnection.withLocalPortForwarding(...)` after the local
/// listener is bound. If `localPort` was `0`, this value contains the actual
/// assigned port.
public struct SSHLocalPortForward: Equatable, Sendable {
    /// Local host name or address.
    public let localHost: String
    /// Local port number.
    public let localPort: UInt16
    /// Target host name or address.
    public let targetHost: String
    /// Target port number.
    public let targetPort: UInt16

    init(
        localHost: String,
        localPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        self.localHost = localHost
        self.localPort = localPort
        self.targetHost = targetHost
        self.targetPort = targetPort
    }
}
struct SSHLocalPortForwardService: Sendable {
    private let client: SSHTransportProtocolClient
    private let lifetime: SSHConnectionLifetime
    private let requestedForward: SSHLocalPortForward
    private let transportBackendPreference: SSHTCPTransportBackendPreference
    private let bridge: SSHPortForwardingBridge

    init(
        client: SSHTransportProtocolClient,
        lifetime: SSHConnectionLifetime,
        requestedForward: SSHLocalPortForward,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        bridge: SSHPortForwardingBridge = SSHPortForwardingBridge()
    ) {
        self.client = client
        self.lifetime = lifetime
        self.requestedForward = requestedForward
        self.transportBackendPreference = transportBackendPreference
        self.bridge = bridge
    }

    func withListener<Result>(
        _ body: (SSHLocalPortForward) async throws -> Result
    ) async throws -> Result {
        let listener = try SSHTCPListenerFactory.makeLifecycleControlledListener(
            localHost: self.requestedForward.localHost,
            localPort: self.requestedForward.localPort,
            preference: self.transportBackendPreference
        )
        let connectionTasks = SSHLocalPortForwardConnectionTasks()
        let connectionMonitor = SSHForwardingConnectionMonitor(
            client: self.client,
            lifetime: self.lifetime
        )

        let listenerTask = Task {
            try await listener.run { acceptedConnection in
                guard let connectionID = await connectionTasks.reserveSlot() else {
                    await acceptedConnection.close()
                    return
                }

                let connectionTask = Task {
                    var didCompleteBridge = false

                    do {
                        try await self.handleAcceptedConnection(acceptedConnection)
                        didCompleteBridge = true
                    } catch is CancellationError {
                    } catch {
                        // Local forwarding behaves like a normal local listener: one failed
                        // accepted connection must not take the listener down for later clients.
                        // Overall SSH liveness still flows through the listener task, fallback
                        // keepalive, and the shared connection lifetime watchers.
                    }

                    if !didCompleteBridge {
                        await acceptedConnection.close()
                    }

                    await connectionTasks.finish(connectionID)
                }
                await connectionTasks.attach(connectionTask, for: connectionID)
            }
        }
        let connectionClosureTask = connectionMonitor.makeConnectionClosureTask {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
        }
        let fallbackLivenessTask = await connectionMonitor.makeFallbackLivenessTaskIfNeeded()
        defer {
            connectionClosureTask.cancel()
            fallbackLivenessTask?.cancel()
        }

        let activeForward: SSHLocalPortForward
        do {
            activeForward = SSHLocalPortForward(
                localHost: self.requestedForward.localHost,
                localPort: try await withTaskCancellationHandler {
                    try await listener.readyPort()
                } onCancel: {
                    listenerTask.cancel()
                },
                targetHost: self.requestedForward.targetHost,
                targetPort: self.requestedForward.targetPort
            )
        } catch {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            throw error
        }

        do {
            let result = try await body(activeForward)
            guard await self.lifetime.active() else {
                await self.cancel(
                    listenerTask: listenerTask,
                    connectionTasks: connectionTasks
                )
                throw SSHClientError.connectionScopeEnded
            }
            try await self.shutdown(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            return result
        } catch {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            guard await self.lifetime.active() else {
                throw SSHClientError.connectionScopeEnded
            }
            throw error
        }
    }

    private func handleAcceptedConnection(
        _ acceptedConnection: SSHTCPAcceptedConnection
    ) async throws {
        let remoteChannel = try await self.client.openDirectTCPIPChannel(
            target: SSHSocketEndpoint(
                host: self.requestedForward.targetHost,
                port: self.requestedForward.targetPort
            ),
            originator: try acceptedConnection.originator(),
            outputBufferingMode: .events
        )

        try await self.bridge.bridge(
            localTransport: acceptedConnection.transport,
            remoteChannel: remoteChannel
        )
    }

    private func shutdown(
        listenerTask: Task<Void, Error>,
        connectionTasks: SSHLocalPortForwardConnectionTasks
    ) async throws {
        await connectionTasks.beginShutdown()

        var listenerError: (any Error)?
        listenerTask.cancel()
        do {
            try await listenerTask.value
        } catch is CancellationError {
        } catch {
            listenerError = error
        }

        await connectionTasks.waitForAll()

        if let listenerError {
            throw listenerError
        }
    }

    private func cancel(
        listenerTask: Task<Void, Error>,
        connectionTasks: SSHLocalPortForwardConnectionTasks
    ) async {
        await connectionTasks.beginShutdown()
        listenerTask.cancel()
        _ = try? await listenerTask.value
        await connectionTasks.waitForAll()
    }
}
private actor SSHLocalPortForwardConnectionTasks {
    private struct Entry {
        var task: Task<Void, Never>?
    }

    private var tasks: [UInt64: Entry] = [:]
    private var nextID: UInt64 = 0
    private var isStopping = false
    private var waitContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]

    func reserveSlot() -> UInt64? {
        guard !self.isStopping else {
            return nil
        }

        let taskID = self.nextID
        self.nextID += 1
        self.tasks[taskID] = Entry(task: nil)
        return taskID
    }

    func attach(_ task: Task<Void, Never>, for taskID: UInt64) {
        guard var entry = self.tasks[taskID] else {
            task.cancel()
            return
        }

        entry.task = task
        self.tasks[taskID] = entry

        if self.isStopping {
            task.cancel()
        }
    }

    func finish(_ taskID: UInt64) {
        self.tasks.removeValue(forKey: taskID)
        self.resumeWaitIfNeeded()
    }

    func beginShutdown() {
        self.isStopping = true

        for entry in self.tasks.values {
            entry.task?.cancel()
        }

        self.resumeWaitIfNeeded()
    }

    func waitForAll() async {
        if self.tasks.isEmpty {
            return
        }

        let waiterID = UUID()
        await withCheckedContinuation { continuation in
            self.installWaitContinuation(continuation, waiterID: waiterID)
        }
    }

    private func installWaitContinuation(
        _ continuation: CheckedContinuation<Void, Never>,
        waiterID: UUID
    ) {
        if self.tasks.isEmpty {
            continuation.resume()
            return
        }

        self.waitContinuations[waiterID] = continuation
    }

    private func resumeWaitIfNeeded() {
        guard self.tasks.isEmpty else {
            return
        }

        let continuations = self.waitContinuations.values
        self.waitContinuations.removeAll(keepingCapacity: false)
        for continuation in continuations {
            continuation.resume()
        }
    }
}
