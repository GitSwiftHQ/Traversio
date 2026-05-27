// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// High-level state of an established `SSHConnection`.
public enum SSHConnectionState: String, Equatable, Sendable {
    /// Ready.
    case ready
    /// Degraded.
    case degraded
    /// Lost.
    case lost
    /// Closed.
    case closed
}

/// Lower-level Network.framework transport state when available.
public enum SSHConnectionTransportState: String, Equatable, Sendable {
    /// Setup.
    case setup
    /// Waiting.
    case waiting
    /// Preparing.
    case preparing
    /// Ready.
    case ready
    /// Failed.
    case failed
    /// Cancelled.
    case cancelled
}

/// Reason a connection state event was emitted.
public enum SSHConnectionStateEventTrigger: String, Equatable, Sendable {
    /// Connected.
    case connected
    /// Transport State Changed.
    case transportStateChanged = "transport-state-changed"
    /// Network Path Changed.
    case networkPathChanged = "network-path-changed"
    /// Transport Viability Changed.
    case transportViabilityChanged = "transport-viability-changed"
    /// Better Path Available.
    case betterPathAvailable = "better-path-available"
    /// Proactive Liveness Check Succeeded.
    case proactiveLivenessCheckSucceeded = "proactive-liveness-check-succeeded"
    /// Background Failure.
    case backgroundFailure = "background-failure"
    /// Closed.
    case closed
}

/// Network path reachability state when available.
public enum SSHConnectionNetworkPathStatus: String, Equatable, Sendable {
    /// Satisfied.
    case satisfied
    /// Unsatisfied.
    case unsatisfied
    /// Requires Connection.
    case requiresConnection = "requires-connection"
}

/// Network interface type reported by the active path when available.
public enum SSHConnectionNetworkInterface: String, Equatable, Sendable {
    /// Wifi.
    case wifi
    /// Cellular.
    case cellular
    /// Wired Ethernet.
    case wiredEthernet = "wired-ethernet"
    /// Loopback.
    case loopback
    /// Other.
    case other
}

/// Snapshot of the current network path for an SSH connection.
public struct SSHConnectionNetworkPath: Equatable, Sendable {
    /// Status.
    public let status: SSHConnectionNetworkPathStatus
    /// Available Interfaces.
    public let availableInterfaces: [SSHConnectionNetworkInterface]
    /// Is Expensive.
    public let isExpensive: Bool
    /// Is Constrained.
    public let isConstrained: Bool
    /// Supports I Pv4.
    public let supportsIPv4: Bool
    /// Supports I Pv6.
    public let supportsIPv6: Bool
    /// Creates an SSHConnectionNetworkPath.

    public init(
        status: SSHConnectionNetworkPathStatus,
        availableInterfaces: [SSHConnectionNetworkInterface],
        isExpensive: Bool,
        isConstrained: Bool,
        supportsIPv4: Bool,
        supportsIPv6: Bool
    ) {
        self.status = status
        self.availableInterfaces = availableInterfaces
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
    }
}

/// Point-in-time connection state used by `currentState()` and state events.
public struct SSHConnectionStateSnapshot: Equatable, Sendable {
    /// State.
    public let state: SSHConnectionState
    /// Transport State.
    public let transportState: SSHConnectionTransportState?
    /// Network Path.
    public let networkPath: SSHConnectionNetworkPath?
    /// Is Transport Viable.
    public let isTransportViable: Bool?
    /// Better Path Available.
    public let betterPathAvailable: Bool?
    /// Detail.
    public let detail: String?
    /// Creates an SSHConnectionStateSnapshot.

    public init(
        state: SSHConnectionState,
        transportState: SSHConnectionTransportState? = nil,
        networkPath: SSHConnectionNetworkPath? = nil,
        isTransportViable: Bool? = nil,
        betterPathAvailable: Bool? = nil,
        detail: String? = nil
    ) {
        self.state = state
        self.transportState = transportState
        self.networkPath = networkPath
        self.isTransportViable = isTransportViable
        self.betterPathAvailable = betterPathAvailable
        self.detail = detail
    }
}

/// One emitted connection state change.
public struct SSHConnectionStateEvent: Equatable, Sendable {
    /// Trigger.
    public let trigger: SSHConnectionStateEventTrigger
    /// Snapshot.
    public let snapshot: SSHConnectionStateSnapshot
    /// Creates an SSHConnectionStateEvent.

    public init(
        trigger: SSHConnectionStateEventTrigger,
        snapshot: SSHConnectionStateSnapshot
    ) {
        self.trigger = trigger
        self.snapshot = snapshot
    }
}

/// Async sequence of connection state changes.
public struct SSHConnectionStateEventSequence: AsyncSequence, Sendable {
    /// Element type produced by this async sequence.
    public typealias Element = SSHConnectionStateEvent

    private let stream: AsyncStream<SSHConnectionStateEvent>

    fileprivate init(stream: AsyncStream<SSHConnectionStateEvent>) {
        self.stream = stream
    }

    /// Creates an async iterator for this sequence.
    public func makeAsyncIterator() -> AsyncStream<SSHConnectionStateEvent>.Iterator {
        self.stream.makeAsyncIterator()
    }
}

package extension SSHConnectionStateEventSequence {
    static let finished = Self(
        stream: AsyncStream { continuation in
            continuation.finish()
        }
    )
}

package actor SSHConnectionStateCoordinator {
    private static let defaultReadySnapshot = SSHConnectionStateSnapshot(state: .ready)

    private final class EventEmitter: @unchecked Sendable {
        // Sendable invariant: the continuation is created once during initialization,
        // then all event emission is serialized by `SSHConnectionStateCoordinator`.
        let sequence: SSHConnectionStateEventSequence
        let continuation: AsyncStream<SSHConnectionStateEvent>.Continuation

        init() {
            var capturedContinuation: AsyncStream<SSHConnectionStateEvent>.Continuation?
            let stream = AsyncStream<SSHConnectionStateEvent> { continuation in
                capturedContinuation = continuation
            }
            self.sequence = SSHConnectionStateEventSequence(stream: stream)
            self.continuation = capturedContinuation!
        }
    }

    nonisolated let stateEvents: SSHConnectionStateEventSequence

    private let client: SSHTransportProtocolClient
    private let logHandler: SSHClientLogHandler
    private let emitter: EventEmitter
    private var snapshot: SSHConnectionStateSnapshot
    private var didReachTerminalState = false
    private var proactiveLivenessProbeTask: Task<Void, Never>?

    init(
        client: SSHTransportProtocolClient,
        logHandler: SSHClientLogHandler
    ) {
        let emitter = EventEmitter()
        self.client = client
        self.logHandler = logHandler
        self.emitter = emitter
        self.stateEvents = emitter.sequence
        self.snapshot = Self.defaultReadySnapshot
        let event = SSHConnectionStateEvent(
            trigger: .connected,
            snapshot: self.snapshot
        )
        emitter.continuation.yield(event)
        logHandler.logConnectionStateEvent(event)
    }

    func currentSnapshot() -> SSHConnectionStateSnapshot {
        self.snapshot
    }

    func recordExplicitClose() {
        guard !self.didReachTerminalState else {
            return
        }

        self.didReachTerminalState = true
        self.snapshot = SSHConnectionStateSnapshot(
            state: .closed,
            transportState: self.snapshot.transportState,
            networkPath: self.snapshot.networkPath,
            isTransportViable: self.snapshot.isTransportViable,
            betterPathAvailable: self.snapshot.betterPathAvailable,
            detail: self.snapshot.detail
        )
        self.emit(.closed)
        self.proactiveLivenessProbeTask?.cancel()
        self.proactiveLivenessProbeTask = nil
        self.emitter.continuation.finish()
    }

    func recordBackgroundFailure(_ error: any Error & Sendable) {
        guard !self.didReachTerminalState else {
            return
        }

        self.didReachTerminalState = true
        self.snapshot = SSHConnectionStateSnapshot(
            state: .lost,
            transportState: self.snapshot.transportState,
            networkPath: self.snapshot.networkPath,
            isTransportViable: self.snapshot.isTransportViable,
            betterPathAvailable: self.snapshot.betterPathAvailable,
            detail: SSHConnectionStateErrorDescription.describe(error)
        )
        self.emit(.backgroundFailure)
        self.proactiveLivenessProbeTask?.cancel()
        self.proactiveLivenessProbeTask = nil
        self.emitter.continuation.finish()
    }

    func recordTransportObservation(_ event: SSHTransportObservationEvent) -> Bool {
        guard !self.didReachTerminalState else {
            return false
        }

        let trigger: SSHConnectionStateEventTrigger
        let shouldProbe: Bool
        let terminalObservationFailure: SSHConnectionStateTransportObservationFailure?

        switch event {
        case let .stateChanged(state, detail):
            self.snapshot = SSHConnectionStateSnapshot(
                state: self.classifiedState(
                    transportState: Self.connectionTransportState(from: state),
                    networkPath: self.snapshot.networkPath,
                    isTransportViable: self.snapshot.isTransportViable,
                    explicitState: nil
                ),
                transportState: Self.connectionTransportState(from: state),
                networkPath: self.snapshot.networkPath,
                isTransportViable: self.snapshot.isTransportViable,
                betterPathAvailable: self.snapshot.betterPathAvailable,
                detail: detail
            )
            trigger = .transportStateChanged
            shouldProbe = false
            if state == .failed || state == .cancelled {
                terminalObservationFailure = SSHConnectionStateTransportObservationFailure(
                    state: state,
                    detail: detail
                )
            } else {
                terminalObservationFailure = nil
            }
        case let .networkPathChanged(networkPath):
            let path = Self.connectionNetworkPath(from: networkPath)
            self.snapshot = SSHConnectionStateSnapshot(
                state: self.classifiedState(
                    transportState: self.snapshot.transportState,
                    networkPath: path,
                    isTransportViable: self.snapshot.isTransportViable,
                    explicitState: nil
                ),
                transportState: self.snapshot.transportState,
                networkPath: path,
                isTransportViable: self.snapshot.isTransportViable,
                betterPathAvailable: self.snapshot.betterPathAvailable,
                detail: self.snapshot.detail
            )
            trigger = .networkPathChanged
            shouldProbe = path.status == .satisfied
            terminalObservationFailure = nil
        case let .viabilityChanged(isTransportViable):
            self.snapshot = SSHConnectionStateSnapshot(
                state: self.classifiedState(
                    transportState: self.snapshot.transportState,
                    networkPath: self.snapshot.networkPath,
                    isTransportViable: isTransportViable,
                    explicitState: nil
                ),
                transportState: self.snapshot.transportState,
                networkPath: self.snapshot.networkPath,
                isTransportViable: isTransportViable,
                betterPathAvailable: self.snapshot.betterPathAvailable,
                detail: self.snapshot.detail
            )
            trigger = .transportViabilityChanged
            shouldProbe = isTransportViable
            terminalObservationFailure = nil
        case let .betterPathAvailable(hasBetterPath):
            self.snapshot = SSHConnectionStateSnapshot(
                state: self.classifiedState(
                    transportState: self.snapshot.transportState,
                    networkPath: self.snapshot.networkPath,
                    isTransportViable: self.snapshot.isTransportViable,
                    explicitState: nil
                ),
                transportState: self.snapshot.transportState,
                networkPath: self.snapshot.networkPath,
                isTransportViable: self.snapshot.isTransportViable,
                betterPathAvailable: hasBetterPath,
                detail: self.snapshot.detail
            )
            trigger = .betterPathAvailable
            shouldProbe = hasBetterPath
            terminalObservationFailure = nil
        }

        self.emit(trigger)

        if let terminalObservationFailure {
            self.recordBackgroundFailure(terminalObservationFailure)
            return true
        }

        guard shouldProbe else {
            return false
        }

        self.proactiveLivenessProbeTask?.cancel()
        let coordinator = self
        self.proactiveLivenessProbeTask = Task {
            await coordinator.performProactiveLivenessProbe()
        }
        return false
    }

    private func performProactiveLivenessProbe() async {
        let probeRan: Bool

        do {
            probeRan = try await self.client.probeTransportLivenessAfterNetworkChange()
        } catch {
            return
        }

        guard probeRan, !self.didReachTerminalState else {
            return
        }

        self.snapshot = SSHConnectionStateSnapshot(
            state: self.classifiedState(
                transportState: self.snapshot.transportState,
                networkPath: self.snapshot.networkPath,
                isTransportViable: self.snapshot.isTransportViable,
                explicitState: nil
            ),
            transportState: self.snapshot.transportState,
            networkPath: self.snapshot.networkPath,
            isTransportViable: self.snapshot.isTransportViable,
            betterPathAvailable: self.snapshot.betterPathAvailable,
            detail: nil
        )
        self.emit(.proactiveLivenessCheckSucceeded)
    }

    private func emit(_ trigger: SSHConnectionStateEventTrigger) {
        let event = SSHConnectionStateEvent(
            trigger: trigger,
            snapshot: self.snapshot
        )
        self.emitter.continuation.yield(event)
        self.logHandler.logConnectionStateEvent(event)
    }

    private func classifiedState(
        transportState: SSHConnectionTransportState?,
        networkPath: SSHConnectionNetworkPath?,
        isTransportViable: Bool?,
        explicitState: SSHConnectionState?
    ) -> SSHConnectionState {
        if let explicitState {
            return explicitState
        }

        if let transportState {
            switch transportState {
            case .waiting, .failed, .cancelled:
                return .degraded
            case .setup, .preparing, .ready:
                break
            }
        }

        if isTransportViable == false {
            return .degraded
        }

        if let networkPath, networkPath.status != .satisfied {
            return .degraded
        }

        return .ready
    }

    private static func connectionTransportState(
        from state: SSHTransportObservedState
    ) -> SSHConnectionTransportState {
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
        }
    }

    private static func connectionNetworkPath(
        from path: SSHTransportNetworkPath
    ) -> SSHConnectionNetworkPath {
        SSHConnectionNetworkPath(
            status: self.connectionNetworkPathStatus(from: path.status),
            availableInterfaces: path.availableInterfaces.map(self.connectionNetworkInterface),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6
        )
    }

    private static func connectionNetworkPathStatus(
        from status: SSHTransportNetworkPathStatus
    ) -> SSHConnectionNetworkPathStatus {
        switch status {
        case .satisfied:
            return .satisfied
        case .unsatisfied:
            return .unsatisfied
        case .requiresConnection:
            return .requiresConnection
        }
    }

    private static func connectionNetworkInterface(
        _ interface: SSHTransportNetworkInterface
    ) -> SSHConnectionNetworkInterface {
        switch interface {
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
        }
    }
}

package actor SSHConnectionTransportObservationBuffer {
    private var bufferedEvents: [SSHTransportObservationEvent] = []
    private var handler: (@Sendable (SSHTransportObservationEvent) async -> Void)?

    func record(_ event: SSHTransportObservationEvent) async {
        if let handler {
            await handler(event)
            return
        }

        self.bufferedEvents.append(event)
    }

    func attach(
        _ handler: @escaping @Sendable (SSHTransportObservationEvent) async -> Void
    ) async {
        let bufferedEvents = self.bufferedEvents
        self.bufferedEvents.removeAll(keepingCapacity: false)
        self.handler = handler

        for event in bufferedEvents {
            await handler(event)
        }
    }
}

package enum SSHConnectionStateErrorDescription {
    static func describe(_ error: any Error) -> String {
        switch error {
        case let error as LocalizedError:
            if let description = error.errorDescription {
                return description
            }
        default:
            break
        }

        let description = String(describing: error)
        guard !description.isEmpty else {
            return String(describing: type(of: error))
        }
        return description
    }
}

package struct SSHConnectionStateTransportObservationFailure: Error, Equatable, Sendable, CustomStringConvertible {
    package let state: SSHTransportObservedState
    package let detail: String?

    package var description: String {
        if let detail, !detail.isEmpty {
            return "transport observation reported \(self.state.rawValue): \(detail)"
        }

        return "transport observation reported \(self.state.rawValue)"
    }
}
