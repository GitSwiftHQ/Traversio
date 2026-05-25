// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network
/// Complete data collected from an accepted remote TCP forwarding channel.
public struct SSHForwardedTCPIPChannelOutput: Equatable, Sendable {
    /// Collected channel data.
    public let data: [UInt8]
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(transcript: SSHTCPIPChannelTranscript) {
        self.data = transcript.data
        self.didReceiveEOF = transcript.didReceiveEOF
    }
}
/// One inbound connection accepted by a remote TCP forwarding listener.
///
/// Use this type when the app handles forwarded channels itself instead of
/// asking Traversio to bridge them to a local TCP endpoint.
public struct SSHForwardedTCPIPChannel: Sendable {
    /// Listening Host.
    public let listeningHost: String
    /// Listening Port.
    public let listeningPort: UInt16
    /// Originator Host.
    public let originatorHost: String
    /// Originator Port.
    public let originatorPort: UInt16

    let handle: SSHTCPIPChannelHandle
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        acceptedChannel: SSHAcceptedForwardedTCPIPChannel,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.listeningHost = acceptedChannel.openRequest.listeningAddress
        self.listeningPort = acceptedChannel.openRequest.listeningPort
        self.originatorHost = acceptedChannel.openRequest.originatorAddress
        self.originatorPort = acceptedChannel.openRequest.originatorPort
        self.handle = acceptedChannel.handle
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Writes bytes to the forwarded channel.
    public func write(_ bytes: [UInt8]) async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedTCPIPChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.write(bytes)
        }
    }

    /// Writes UTF-8 text to the forwarded channel.
    public func write(_ string: String) async throws {
        try await self.write(Array(string.utf8))
    }

    /// Sends channel EOF.
    public func sendEOF() async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedTCPIPChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.sendEOF()
        }
    }

    /// Closes this forwarded channel.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedTCPIPChannel,
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
            scope: .forwardedTCPIPChannel,
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
            scope: .forwardedTCPIPChannel,
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
            scope: .forwardedTCPIPChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.adjustReceiveWindow(by: byteCount)
        }
    }

    /// Reads the next structured channel event.
    public func nextEvent() async throws -> SSHTCPIPChannelEvent? {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedTCPIPChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.readEvent()
        }
    }

    /// Events.
    public var events: SSHTCPIPChannelEventSequence {
        SSHTCPIPChannelEventSequence(
            nextEventReader: { try await self.nextEvent() },
            cancelHandler: { await self.bestEffortCloseOnCancellation() }
        )
    }

    func bestEffortCloseOnCancellation() async {
        await self.handle.bestEffortCloseIgnoringCancellation()
    }

    /// Collects channel data until the remote side closes the channel.
    public func collectDataUntilClose() async throws -> SSHForwardedTCPIPChannelOutput {
        try await self.lifetime.requireActive()
        let transcript = try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.handle.diagnosticsSnapshot() },
            scope: .forwardedTCPIPChannel,
            logHandler: self.logHandler,
            localChannelID: self.handle.channel.localChannelID,
            remoteChannelID: self.handle.channel.remoteChannelID
        ) {
            try await self.handle.collectDataUntilClose()
        }
        return SSHForwardedTCPIPChannelOutput(transcript: transcript)
    }
}
/// A remote TCP listener created by the SSH server for remote forwarding.
///
/// The listener exists only inside the `withRemotePortForwardListener(...)`
/// body that created it.
public struct SSHRemotePortForwardListener: Sendable {
    /// Remote host name or address.
    public let remoteHost: String
    /// Remote port number.
    public let remotePort: UInt16

    private let client: SSHTransportProtocolClient
    private let activeForward: SSHTCPIPForwardingRequest
    private let state: SSHRemotePortForwardListenerState
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        client: SSHTransportProtocolClient,
        activeForward: SSHTCPIPForwardingRequest,
        state: SSHRemotePortForwardListenerState,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.remoteHost = activeForward.addressToBind
        self.remotePort = activeForward.portToBind
        self.client = client
        self.activeForward = activeForward
        self.state = state
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Waits for and returns the next forwarded TCP/IP channel.
    public func accept() async throws -> SSHForwardedTCPIPChannel {
        try await self.lifetime.requireActive()
        return try await withOperationFailureMapping(
            metadata: self.metadata,
            snapshotProvider: { await self.state.diagnosticsSnapshot() },
            scope: .remotePortForwardListener,
            logHandler: self.logHandler
        ) {
            try await self.state.accept()
        }
    }

    func shutdownForwardingScope() async throws {
        try await shutdownRemotePortForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime
        )
    }

    func cancelForwardingScope() async {
        await cancelRemotePortForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime
        )
    }

    func beginForwardingScopeShutdown() async {
        await self.state.beginShutdown(
            cancelCurrentAcceptTask: false,
            waitForDrain: false
        )
    }

    func shutdownForwardingScopeAfterShutdownBegan() async throws {
        try await shutdownRemotePortForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime,
            beginShutdown: false
        )
    }

    func cancelForwardingScopeAfterShutdownBegan() async {
        await cancelRemotePortForwardListener(
            client: self.client,
            activeForward: self.activeForward,
            state: self.state,
            lifetime: self.lifetime,
            beginShutdown: false
        )
    }
}
struct SSHRemotePortForwardListenerService: Sendable {
    private let client: SSHTransportProtocolClient
    private let requestedForward: SSHTCPIPForwardingRequest
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        client: SSHTransportProtocolClient,
        requestedForward: SSHTCPIPForwardingRequest,
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
        _ body: (SSHRemotePortForwardListener) async throws -> Result
    ) async throws -> Result {
        let activeForward = try await self.client.requestTCPIPForward(
            addressToBind: self.requestedForward.addressToBind,
            portToBind: self.requestedForward.portToBind
        )
        let state = SSHRemotePortForwardListenerState(
            client: self.client,
            activeForward: activeForward,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
        let listener = SSHRemotePortForwardListener(
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
        activeForward: SSHTCPIPForwardingRequest,
        state: SSHRemotePortForwardListenerState
    ) async throws {
        try await shutdownRemotePortForwardListener(
            client: self.client,
            activeForward: activeForward,
            state: state,
            lifetime: self.lifetime
        )
    }

    private func cancel(
        activeForward: SSHTCPIPForwardingRequest,
        state: SSHRemotePortForwardListenerState
    ) async {
        await cancelRemotePortForwardListener(
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
           requestType == "cancel-tcpip-forward" {
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

private func shutdownRemotePortForwardListener(
    client: SSHTransportProtocolClient,
    activeForward: SSHTCPIPForwardingRequest,
    state: SSHRemotePortForwardListenerState,
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
            try await client.cancelTCPIPForward(activeForward)
        } catch is CancellationError {
        } catch {
            cancelError = error
        }
    }

    if let cancelError,
       SSHRemotePortForwardListenerService.requiresConnectionClosureAfterShutdownFailure(cancelError) {
        await lifetime.close()
    }

    await state.beginShutdown(
        cancelCurrentAcceptTask: true,
        waitForDrain: true
    )

    if let cancelError,
       !SSHRemotePortForwardListenerService.isExpectedShutdownError(cancelError) {
        throw cancelError
    }
}

private func cancelRemotePortForwardListener(
    client: SSHTransportProtocolClient,
    activeForward: SSHTCPIPForwardingRequest,
    state: SSHRemotePortForwardListenerState,
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
            try await client.cancelTCPIPForward(activeForward)
        } catch {
            cancelError = error
        }
    }

    if let cancelError,
       SSHRemotePortForwardListenerService.requiresConnectionClosureAfterShutdownFailure(cancelError) {
        await lifetime.close()
    }
    await state.beginShutdown(
        cancelCurrentAcceptTask: true,
        waitForDrain: true
    )
}

actor SSHRemotePortForwardListenerState {
    private let client: SSHTransportProtocolClient
    private let activeForward: SSHTCPIPForwardingRequest
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    private var waitingOrder: [UUID] = []
    private var waitingContinuations: [UUID: CheckedContinuation<SSHForwardedTCPIPChannel, Error>] = [:]
    private var currentAcceptWaiterID: UUID?
    private var currentAcceptTask: Task<Void, Never>?
    private var drainContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var isClosing = false
    private var didRequestForwardCancellation = false

    init(
        client: SSHTransportProtocolClient,
        activeForward: SSHTCPIPForwardingRequest,
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

    func accept() async throws -> SSHForwardedTCPIPChannel {
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
                let acceptedChannel = try await self.client.acceptForwardedTCPIPChannel(
                    for: self.activeForward
                )
                await self.finishCurrentAccept(
                    for: waiterID,
                    result: .success(
                        SSHForwardedTCPIPChannel(
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
        result: Result<SSHForwardedTCPIPChannel, any Error>
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
