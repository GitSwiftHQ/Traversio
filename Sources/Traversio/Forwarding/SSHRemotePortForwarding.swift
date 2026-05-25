// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

typealias SSHRemotePortForwardBridgeHandler =
    @Sendable (any SSHByteStreamTransport, SSHTCPIPChannelHandle) async throws -> Void

/// Active remote TCP forwarding bridge details.
///
/// Returned from `SSHConnection.withRemotePortForwarding(...)` after the remote
/// listener is accepted by the server.
public struct SSHRemotePortForward: Equatable, Sendable {
    /// Local host name or address.
    public let localHost: String
    /// Local port number.
    public let localPort: UInt16
    /// Remote host name or address.
    public let remoteHost: String
    /// Remote port number.
    public let remotePort: UInt16

    init(
        localHost: String,
        localPort: UInt16,
        remoteHost: String,
        remotePort: UInt16
    ) {
        self.localHost = localHost
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }
}
struct SSHRemotePortForwardService: Sendable {
    private let listenerService: SSHRemotePortForwardListenerService
    private let connectionMonitor: SSHForwardingConnectionMonitor
    private let requestedForward: SSHRemotePortForward
    private let transportBackendPreference: SSHTCPTransportBackendPreference
    private let bridgeHandler: SSHRemotePortForwardBridgeHandler

    init(
        client: SSHTransportProtocolClient,
        requestedForward: SSHRemotePortForward,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        bridge: SSHPortForwardingBridge = SSHPortForwardingBridge(),
        bridgeHandler: SSHRemotePortForwardBridgeHandler? = nil
    ) {
        self.listenerService = SSHRemotePortForwardListenerService(
            client: client,
            requestedForward: SSHTCPIPForwardingRequest(
                addressToBind: requestedForward.remoteHost,
                portToBind: requestedForward.remotePort
            ),
            lifetime: lifetime,
            metadata: metadata,
            logHandler: logHandler
        )
        self.connectionMonitor = SSHForwardingConnectionMonitor(
            client: client,
            lifetime: lifetime
        )
        self.requestedForward = requestedForward
        self.transportBackendPreference = transportBackendPreference
        self.bridgeHandler = bridgeHandler ?? { localTransport, remoteChannel in
            try await bridge.bridge(
                localTransport: localTransport,
                remoteChannel: remoteChannel
            )
        }
    }

    func withForward<Result>(
        _ body: (SSHRemotePortForward) async throws -> Result
    ) async throws -> Result {
        let runtime = SSHRemotePortForwardRuntime()
        do {
            return try await self.listenerService.withListener { listener in
                let activeForward = SSHRemotePortForward(
                    localHost: self.requestedForward.localHost,
                    localPort: self.requestedForward.localPort,
                    remoteHost: listener.remoteHost,
                    remotePort: listener.remotePort
                )
                let connectionTasks = SSHRemotePortForwardConnectionTasks()
                let readiness = SSHRemotePortForwardAcceptLoopReadiness()
                let acceptTask = Task {
                    do {
                        try await self.runAcceptLoop(
                            listener: listener,
                            connectionTasks: connectionTasks,
                            readiness: readiness
                        )
                    } catch {
                        await self.connectionMonitor.closeLifetimeIfNeeded(for: error)
                        await readiness.markFailed(error)
                        throw error
                    }
                }
                await runtime.store(
                    acceptTask: acceptTask,
                    connectionTasks: connectionTasks
                )

                do {
                    try await withTaskCancellationHandler {
                        try await readiness.waitUntilReady()
                    } onCancel: {
                        acceptTask.cancel()
                    }
                    let result = try await body(activeForward)
                    try await SSHForwardingCleanup.performIgnoringCallerCancellation {
                        try await self.shutdown(
                            listener: listener,
                            acceptTask: acceptTask,
                            connectionTasks: connectionTasks
                        )
                    }
                    return result
                } catch {
                    await listener.beginForwardingScopeShutdown()
                    await connectionTasks.beginShutdown(cancelActiveTasks: true)
                    await connectionTasks.waitForAttachedTasks()
                    await SSHForwardingCleanup.performIgnoringCallerCancellation {
                        await listener.cancelForwardingScopeAfterShutdownBegan()
                        acceptTask.cancel()
                        _ = try? await acceptTask.value
                    }
                    throw error
                }
            }
        } catch {
            await SSHForwardingCleanup.performIgnoringCallerCancellation {
                await self.finishAfterListenerShutdown(runtime: runtime)
            }
            throw error
        }
    }

    private func runAcceptLoop(
        listener: SSHRemotePortForwardListener,
        connectionTasks: SSHRemotePortForwardConnectionTasks,
        readiness: SSHRemotePortForwardAcceptLoopReadiness
    ) async throws {
        var didSignalReadiness = false

        while let connectionID = await connectionTasks.reserveSlot() {
            do {
                if !didSignalReadiness {
                    await readiness.markReady()
                    didSignalReadiness = true
                }
                let acceptedChannel = try await listener.accept()
                let connectionTask = Task {
                    var didCompleteBridge = false

                    do {
                        try await self.handleAcceptedChannel(acceptedChannel)
                        didCompleteBridge = true
                    } catch is CancellationError {
                    } catch {
                        // Remote fixed-endpoint forwarding should behave like a long-lived
                        // listener: one failed accepted remote connection must not poison the
                        // whole listener scope for later remote clients. Overall SSH liveness
                        // still flows through the listener task, fallback keepalive, and the
                        // shared connection lifetime watchers.
                    }

                    if !didCompleteBridge {
                        try? await acceptedChannel.handle.close()
                    }

                    await connectionTasks.finish(connectionID)
                }
                await connectionTasks.attach(connectionTask, for: connectionID)
            } catch is CancellationError {
                await connectionTasks.finish(connectionID)
                throw CancellationError()
            } catch {
                await connectionTasks.finish(connectionID)
                throw error
            }
        }
    }

    private func handleAcceptedChannel(
        _ acceptedChannel: SSHForwardedTCPIPChannel
    ) async throws {
        try await SSHTCPByteStreamTransportFactory.withConnected(
            to: SSHSocketEndpoint(
                host: self.requestedForward.localHost,
                port: self.requestedForward.localPort
            ),
            preference: self.transportBackendPreference
        ) { localTransport in
            try await self.bridgeHandler(localTransport, acceptedChannel.handle)
        }
    }

    private func finishAfterListenerShutdown(
        runtime: SSHRemotePortForwardRuntime
    ) async {
        guard let storedRuntime = await runtime.value() else {
            return
        }

        let acceptTask = storedRuntime.acceptTask
        let connectionTasks = storedRuntime.connectionTasks

        _ = try? await acceptTask.value
        await connectionTasks.waitForAll()
        acceptTask.cancel()
        _ = try? await acceptTask.value
    }

    private func shutdown(
        listener: SSHRemotePortForwardListener,
        acceptTask: Task<Void, Error>,
        connectionTasks: SSHRemotePortForwardConnectionTasks
    ) async throws {
        await connectionTasks.beginShutdown(cancelActiveTasks: false)

        await listener.beginForwardingScopeShutdown()
        try await listener.shutdownForwardingScopeAfterShutdownBegan()

        acceptTask.cancel()
        _ = try? await acceptTask.value

        await connectionTasks.waitForAll()
    }
}

private struct SSHRemotePortForwardStoredRuntime: Sendable {
    let acceptTask: Task<Void, Error>
    let connectionTasks: SSHRemotePortForwardConnectionTasks
}

private actor SSHRemotePortForwardRuntime {
    private var storedRuntime: SSHRemotePortForwardStoredRuntime?

    func store(
        acceptTask: Task<Void, Error>,
        connectionTasks: SSHRemotePortForwardConnectionTasks
    ) {
        self.storedRuntime = SSHRemotePortForwardStoredRuntime(
            acceptTask: acceptTask,
            connectionTasks: connectionTasks
        )
    }

    func value() -> SSHRemotePortForwardStoredRuntime? {
        self.storedRuntime
    }
}
private actor SSHRemotePortForwardAcceptLoopReadiness {
    private var continuation: CheckedContinuation<Void, Error>?
    private var result: Result<Void, Error>?

    func waitUntilReady() async throws {
        if let result = self.result {
            return try result.get()
        }

        try await withCheckedThrowingContinuation { continuation in
            precondition(
                self.continuation == nil,
                "remote port forward readiness already waiting"
            )
            self.continuation = continuation
        }
    }

    func markReady() {
        self.finish(with: .success(()))
    }

    func markFailed(_ error: any Error) {
        self.finish(with: .failure(error))
    }

    private func finish(with result: Result<Void, Error>) {
        guard self.result == nil else {
            return
        }

        self.result = result
        switch result {
        case .success:
            self.continuation?.resume()
        case let .failure(error):
            self.continuation?.resume(throwing: error)
        }
        self.continuation = nil
    }
}
private actor SSHRemotePortForwardConnectionTasks {
    private struct Entry {
        var task: Task<Void, Never>?
    }

    private var tasks: [UInt64: Entry] = [:]
    private var nextID: UInt64 = 0
    private var isStopping = false
    private var waitContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var attachedTaskWaitContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]

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
        self.resumeAttachedTaskWaitIfNeeded()
        self.resumeWaitIfNeeded()
    }

    func beginShutdown(cancelActiveTasks: Bool) {
        self.isStopping = true

        guard cancelActiveTasks else {
            self.resumeWaitIfNeeded()
            return
        }

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

    func waitForAttachedTasks() async {
        guard self.hasAttachedTasks() else {
            return
        }

        let waiterID = UUID()
        await withCheckedContinuation { continuation in
            self.installAttachedTaskWaitContinuation(continuation, waiterID: waiterID)
        }
    }

    private func installAttachedTaskWaitContinuation(
        _ continuation: CheckedContinuation<Void, Never>,
        waiterID: UUID
    ) {
        guard self.hasAttachedTasks() else {
            continuation.resume()
            return
        }

        self.attachedTaskWaitContinuations[waiterID] = continuation
    }

    private func hasAttachedTasks() -> Bool {
        self.tasks.values.contains { $0.task != nil }
    }

    private func resumeAttachedTaskWaitIfNeeded() {
        guard !self.hasAttachedTasks() else {
            return
        }

        let continuations = self.attachedTaskWaitContinuations.values
        self.attachedTaskWaitContinuations.removeAll(keepingCapacity: false)
        for continuation in continuations {
            continuation.resume()
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
