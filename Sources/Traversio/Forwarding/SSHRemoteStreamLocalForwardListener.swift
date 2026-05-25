// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network

/// One inbound connection accepted by an OpenSSH remote streamlocal listener.
public struct SSHForwardedStreamLocalChannel: Sendable {
    /// Unix-domain socket path.
    public let socketPath: String

    let handle: SSHTCPIPChannelHandle
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        acceptedChannel: SSHAcceptedForwardedStreamLocalChannel,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.socketPath = acceptedChannel.openRequest.socketPath
        self.handle = acceptedChannel.handle
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Writes bytes to the forwarded streamlocal channel.
    public func write(_ bytes: [UInt8]) async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.write(bytes)
        }
    }

    /// Writes UTF-8 text to the forwarded streamlocal channel.
    public func write(_ string: String) async throws {
        try await self.write(Array(string.utf8))
    }

    /// Sends channel EOF.
    public func sendEOF() async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.sendEOF()
        }
    }

    /// Closes this forwarded streamlocal channel.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.close()
        }
    }

    /// Reads the next data chunk, or `nil` after EOF or close.
    public func readChunk() async throws -> [UInt8]? {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.readChunk()
        }
    }

    /// Returns current receive and send window counters.
    public func channelWindowSnapshot() async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.channelWindowSnapshot()
        }
    }

    /// Manually increases the local receive window.
    public func adjustReceiveWindow(by byteCount: UInt32) async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.adjustReceiveWindow(by: byteCount)
        }
    }

    /// Reads the next structured streamlocal channel event.
    public func nextEvent() async throws -> SSHStreamLocalChannelEvent? {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.readEvent()
        }
    }

    /// Events.
    public var events: SSHStreamLocalChannelEventSequence {
        SSHStreamLocalChannelEventSequence(
            nextEventReader: { try await self.nextEvent() },
            cancelHandler: { await self.bestEffortCloseOnCancellation() }
        )
    }

    func bestEffortCloseOnCancellation() async {
        await self.handle.bestEffortCloseIgnoringCancellation()
    }

    /// Collects channel data until the remote side closes the channel.
    public func collectDataUntilClose() async throws -> SSHForwardedStreamLocalChannelOutput {
        try await self.lifetime.requireActive()
        let transcript = try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedStreamLocalChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.collectDataUntilClose()
        }
        return SSHForwardedStreamLocalChannelOutput(transcript: transcript)
    }
}

/// An OpenSSH remote streamlocal listener.
///
/// The server must support the OpenSSH streamlocal forwarding extension.
public struct SSHRemoteStreamLocalForwardListener: Sendable {
    /// Unix-domain socket path.
    public let socketPath: String

    private let client: SSHTransportProtocolClient
    private let activeForward: SSHStreamLocalForwardingRequest
    private let state: SSHRemoteStreamLocalForwardListenerState
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        client: SSHTransportProtocolClient,
        activeForward: SSHStreamLocalForwardingRequest,
        state: SSHRemoteStreamLocalForwardListenerState,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.socketPath = activeForward.socketPath
        self.client = client
        self.activeForward = activeForward
        self.state = state
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Waits for and returns the next forwarded streamlocal channel.
    public func accept() async throws -> SSHForwardedStreamLocalChannel {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.state.diagnosticsSnapshot() },
            scope: .remoteStreamLocalForwardListener,
            logHandler: self.logHandler
        ) {
            try await self.state.accept()
        }
    }

    func shutdownForwardingScope() async throws {
        try await shutdownRemoteStreamLocalForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime
        )
    }

    func cancelForwardingScope() async {
        await cancelRemoteStreamLocalForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime
        )
    }
}

struct SSHRemoteStreamLocalForwardListenerService: Sendable {
    private let client: SSHTransportProtocolClient
    private let requestedForward: SSHStreamLocalForwardingRequest
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        client: SSHTransportProtocolClient,
        requestedForward: SSHStreamLocalForwardingRequest,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.client = client
        self.requestedForward = requestedForward
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    func withListener<Result>(
        _ body: (SSHRemoteStreamLocalForwardListener) async throws -> Result
    ) async throws -> Result {
        let activeForward = try await self.client.requestStreamLocalForward(
            socketPath: self.requestedForward.socketPath
        )
        let state = SSHRemoteStreamLocalForwardListenerState(
            client: self.client,
            activeForward: activeForward,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
        let listener = SSHRemoteStreamLocalForwardListener(
            client: self.client,
            activeForward: activeForward,
            state: state,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
        let connectionMonitor = SSHForwardingConnectionMonitor(
            client: self.client,
            lifetime: self.lifetime
        )
        let connectionClosureTask = connectionMonitor.makeConnectionClosureTask {
            await self.cancel(
                activeForward: activeForward,
                state: state
            )
        }
        let fallbackLivenessTask = await connectionMonitor.makeFallbackLivenessTaskIfNeeded()
        defer {
            connectionClosureTask.cancel()
            fallbackLivenessTask?.cancel()
        }

        do {
            let result = try await body(listener)
            guard await self.lifetime.active() else {
                await SSHForwardingCleanup.performIgnoringCallerCancellation {
                    await self.cancel(
                        activeForward: activeForward,
                        state: state
                    )
                }
                throw SSHClientError.connectionScopeEnded
            }
            try await SSHForwardingCleanup.performIgnoringCallerCancellation {
                try await self.shutdown(
                    activeForward: activeForward,
                    state: state
                )
            }
            return result
        } catch {
            let lifetimeWasActiveBeforeCancel = await self.lifetime.active()
            await SSHForwardingCleanup.performIgnoringCallerCancellation {
                await self.cancel(
                    activeForward: activeForward,
                    state: state
                )
            }
            let lifetimeIsStillActiveAfterCancel = await self.lifetime.active()
            let shouldPreserveError = Self.requiresConnectionClosureAfterShutdownFailure(error)
            guard lifetimeWasActiveBeforeCancel
                    || lifetimeIsStillActiveAfterCancel
                    || shouldPreserveError else {
                throw SSHClientError.connectionScopeEnded
            }
            throw error
        }
    }

    private func shutdown(
        activeForward: SSHStreamLocalForwardingRequest,
        state: SSHRemoteStreamLocalForwardListenerState
    ) async throws {
        try await shutdownRemoteStreamLocalForwardListener(
            client: self.client,
            activeForward: activeForward,
            state: state,
            lifetime: self.lifetime
        )
    }

    private func cancel(
        activeForward: SSHStreamLocalForwardingRequest,
        state: SSHRemoteStreamLocalForwardListenerState
    ) async {
        await cancelRemoteStreamLocalForwardListener(
            client: self.client,
            activeForward: activeForward,
            state: state,
            lifetime: self.lifetime
        )
    }

    static func requiresConnectionClosureAfterShutdownFailure(_ error: any Error) -> Bool {
        if Self.isShutdownLivenessFailure(error) {
            return true
        }
        if let connectionError = error as? SSHConnectionError,
           case let .globalRequestFailed(requestType) = connectionError,
           requestType == "cancel-streamlocal-forward@openssh.com" {
            return true
        }
        return false
    }

    static func isShutdownLivenessFailure(_ error: any Error) -> Bool {
        if SSHForwardingConnectionMonitor.isConnectionLivenessFailure(error) {
            return true
        }
        if let networkError = error as? NWError,
           case let .posix(code) = networkError,
           code == POSIXErrorCode(rawValue: 89) {
            return true
        }
        if let posixError = error as? POSIXError,
           posixError.code == POSIXErrorCode(rawValue: 89) {
            return true
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain, nsError.code == 89 {
            return true
        }
        return false
    }

    static func isExpectedShutdownError(_ error: any Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let transportError = error as? SSHTransportError,
           transportError == .endOfStreamBeforePacket {
            return true
        }
        if let networkError = error as? NWError,
           case let .posix(code) = networkError,
           code == POSIXErrorCode(rawValue: 89) {
            return true
        }
        if let posixError = error as? POSIXError,
           posixError.code == POSIXErrorCode(rawValue: 89) {
            return true
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain, nsError.code == 89 {
            return true
        }
        return false
    }
}

private func shutdownRemoteStreamLocalForwardListener(
    client: SSHTransportProtocolClient,
    activeForward: SSHStreamLocalForwardingRequest,
    state: SSHRemoteStreamLocalForwardListenerState,
    lifetime: SSHConnectionLifetime,
    beginShutdown: Bool = true
) async throws {
    if beginShutdown {
        await state.beginShutdown(
            cancelCurrentAcceptTask: false,
            waitForDrain: false
        )
    }

    var cancelError: (any Error)?
    if await state.claimForwardCancellationRequest() {
        do {
            try await client.cancelStreamLocalForward(activeForward)
        } catch is CancellationError {
        } catch {
            cancelError = error
        }
    }

    if let cancelError,
       SSHRemoteStreamLocalForwardListenerService.requiresConnectionClosureAfterShutdownFailure(cancelError) {
        await lifetime.close()
    }

    await state.beginShutdown(
        cancelCurrentAcceptTask: true,
        waitForDrain: true
    )

    if let cancelError,
       !SSHRemoteStreamLocalForwardListenerService.isExpectedShutdownError(cancelError) {
        throw cancelError
    }
}

private func cancelRemoteStreamLocalForwardListener(
    client: SSHTransportProtocolClient,
    activeForward: SSHStreamLocalForwardingRequest,
    state: SSHRemoteStreamLocalForwardListenerState,
    lifetime: SSHConnectionLifetime,
    beginShutdown: Bool = true
) async {
    if beginShutdown {
        await state.beginShutdown(
            cancelCurrentAcceptTask: false,
            waitForDrain: false
        )
    }

    var cancelError: (any Error)?
    if await state.claimForwardCancellationRequest() {
        do {
            try await client.cancelStreamLocalForward(activeForward)
        } catch {
            cancelError = error
        }
    }

    if let cancelError,
       SSHRemoteStreamLocalForwardListenerService.requiresConnectionClosureAfterShutdownFailure(cancelError) {
        await lifetime.close()
    }
    await state.beginShutdown(
        cancelCurrentAcceptTask: true,
        waitForDrain: true
    )
}

actor SSHRemoteStreamLocalForwardListenerState {
    private let client: SSHTransportProtocolClient
    private let activeForward: SSHStreamLocalForwardingRequest
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    private var waitingOrder: [UUID] = []
    private var waitingContinuations: [UUID: CheckedContinuation<SSHForwardedStreamLocalChannel, Error>] = [:]
    private var currentAcceptWaiterID: UUID?
    private var currentAcceptTask: Task<Void, Never>?
    private var drainContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var isClosing = false
    private var didRequestForwardCancellation = false

    init(
        client: SSHTransportProtocolClient,
        activeForward: SSHStreamLocalForwardingRequest,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.client = client
        self.activeForward = activeForward
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    func accept() async throws -> SSHForwardedStreamLocalChannel {
        if self.isClosing {
            throw CancellationError()
        }

        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.waitingOrder.append(waiterID)
                self.waitingContinuations[waiterID] = continuation
                self.startNextAcceptIfNeeded()
            }
        } onCancel: {
            Task {
                await self.cancelWaiter(waiterID)
            }
        }
    }

    func diagnosticsSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.client.diagnosticsSnapshot()
    }

    func beginShutdown(
        cancelCurrentAcceptTask: Bool,
        waitForDrain: Bool
    ) async {
        self.isClosing = true
        self.resumeAllWaiters(throwing: CancellationError())
        if cancelCurrentAcceptTask {
            self.currentAcceptTask?.cancel()
        }
        if waitForDrain {
            await self.waitForDrain()
        }
    }

    func claimForwardCancellationRequest() -> Bool {
        guard !self.didRequestForwardCancellation else {
            return false
        }
        self.didRequestForwardCancellation = true
        return true
    }

    private func startNextAcceptIfNeeded() {
        guard !self.isClosing,
              self.currentAcceptTask == nil,
              let waiterID = self.waitingOrder.first else {
            self.resumeDrainIfNeeded()
            return
        }

        self.currentAcceptWaiterID = waiterID
        self.currentAcceptTask = Task {
            do {
                let acceptedChannel = try await self.client.acceptForwardedStreamLocalChannel(
                    for: self.activeForward
                )
                await self.finishCurrentAccept(
                    for: waiterID,
                    result: .success(
                        SSHForwardedStreamLocalChannel(
                            acceptedChannel: acceptedChannel,
                            lifetime: self.lifetime,
                            metadata: self.metadata,
                            logHandler: self.logHandler
                        )
                    )
                )
            } catch is CancellationError {
                await self.finishCurrentAccept(
                    for: waiterID,
                    result: .failure(CancellationError())
                )
            } catch {
                await self.finishCurrentAccept(
                    for: waiterID,
                    result: .failure(error)
                )
            }
        }
    }

    private func finishCurrentAccept(
        for waiterID: UUID,
        result: Result<SSHForwardedStreamLocalChannel, any Error>
    ) async {
        self.currentAcceptTask = nil
        self.currentAcceptWaiterID = nil

        switch result {
        case let .success(channel):
            if let recipientID = self.waitingOrder.first {
                self.waitingOrder.removeFirst()
                let continuation = self.waitingContinuations.removeValue(forKey: recipientID)
                if let continuation {
                    continuation.resume(returning: channel)
                } else {
                    try? await channel.handle.close()
                }
            } else {
                try? await channel.handle.close()
            }
        case let .failure(error):
            if self.waitingContinuations[waiterID] != nil,
               let index = self.waitingOrder.firstIndex(of: waiterID) {
                self.waitingOrder.remove(at: index)
                let continuation = self.waitingContinuations.removeValue(forKey: waiterID)
                continuation?.resume(throwing: error)
            } else if !self.isClosing && !self.waitingOrder.isEmpty {
                self.startNextAcceptIfNeeded()
                return
            }
        }

        self.startNextAcceptIfNeeded()
    }

    private func cancelWaiter(_ waiterID: UUID) {
        if let index = self.waitingOrder.firstIndex(of: waiterID) {
            self.waitingOrder.remove(at: index)
        }
        let continuation = self.waitingContinuations.removeValue(forKey: waiterID)
        continuation?.resume(throwing: CancellationError())

        if self.waitingOrder.isEmpty {
            self.currentAcceptTask?.cancel()
        } else if waiterID == self.currentAcceptWaiterID {
            // Keep the current accept alive so the next waiter can reuse it.
        }

        self.resumeDrainIfNeeded()
    }

    private func resumeAllWaiters(throwing error: any Error) {
        let waiters = self.waitingOrder
        self.waitingOrder.removeAll(keepingCapacity: false)

        for waiterID in waiters {
            let continuation = self.waitingContinuations.removeValue(forKey: waiterID)
            continuation?.resume(throwing: error)
        }
    }

    private func waitForDrain() async {
        guard self.currentAcceptTask != nil else {
            return
        }

        let waiterID = UUID()
        await withCheckedContinuation { continuation in
            self.installDrainContinuation(continuation, waiterID: waiterID)
        }
    }

    private func installDrainContinuation(
        _ continuation: CheckedContinuation<Void, Never>,
        waiterID: UUID
    ) {
        guard self.currentAcceptTask != nil else {
            continuation.resume()
            return
        }

        self.drainContinuations[waiterID] = continuation
    }

    private func resumeDrainIfNeeded() {
        guard self.currentAcceptTask == nil else {
            return
        }

        let continuations = self.drainContinuations.values
        self.drainContinuations.removeAll(keepingCapacity: false)
        for continuation in continuations {
            continuation.resume()
        }
    }
}
