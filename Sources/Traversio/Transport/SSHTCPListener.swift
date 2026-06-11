// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network
package struct SSHTCPAcceptedConnection: Sendable {
    private let originatorResult: Result<SSHSocketEndpoint, SSHTransportError>

    package let transport: any SSHByteStreamTransport

    package init(
        originatorResult: Result<SSHSocketEndpoint, SSHTransportError>,
        transport: any SSHByteStreamTransport
    ) {
        self.originatorResult = originatorResult
        self.transport = transport
    }

    package func originator() throws -> SSHSocketEndpoint {
        try self.originatorResult.get()
    }

    package func close() async {
        await self.transport.close()
    }
}
package protocol SSHTCPListener: Sendable {
    func readyPort() async throws -> UInt16
    func run(_ handler: @escaping @Sendable (SSHTCPAcceptedConnection) async -> Void) async throws
}
package enum SSHTCPListenerFactory {
    package static func makeListener(
        localHost: String,
        localPort: UInt16,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) throws -> any SSHTCPListener {
        try self.makeListener(
            localHost: localHost,
            localPort: localPort,
            policy: self.policy(
                role: .listener,
                preference: preference
            )
        )
    }

    package static func makeLifecycleControlledListener(
        localHost: String,
        localPort: UInt16,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) throws -> any SSHTCPListener {
        try self.makeListener(
            localHost: localHost,
            localPort: localPort,
            policy: self.policy(
                role: .lifecycleControlledListener,
                preference: preference
            )
        )
    }

    package static func listenerParameters(
        localHost: String,
        localPort: UInt16
    ) throws -> NWParameters {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(localHost),
            port: try SSHTCPEndpointParser.port(localPort)
        )
        parameters.allowLocalEndpointReuse = true
        return parameters
    }

    private static func unavailableModernListenerError() -> SSHTransportError {
        SSHTransportError.unsupportedTransportBackend(
            "The modern Network listener backend requires Apple platform release 26 or newer."
        )
    }

    private static func makeListener(
        localHost: String,
        localPort: UInt16,
        policy: SSHTCPTransportFlowPolicy
    ) throws -> any SSHTCPListener {
        switch policy.selectedBackend {
        case .modernNetworkConnection:
            guard #available(
                macOS 26.0,
                iOS 26.0,
                tvOS 26.0,
                watchOS 26.0,
                visionOS 26.0,
                *
            ) else {
                throw self.unavailableModernListenerError()
            }
            return try NetworkTCPListener(localHost: localHost, localPort: localPort)
        case .legacyNWConnection:
            return try LegacyNetworkTCPListener(localHost: localHost, localPort: localPort)
        }
    }

    private static func policy(
        role: SSHTCPTransportFlowRole,
        preference: SSHTCPTransportBackendPreference
    ) -> SSHTCPTransportFlowPolicy {
        SSHTCPTransportFlowPolicy.resolveCurrentPlatform(
            role: role,
            preference: preference
        )
    }
}
package enum SSHTCPEndpointParser {
    package static func originatorResult(
        for endpoint: NWEndpoint?
    ) -> Result<SSHSocketEndpoint, SSHTransportError> {
        guard let endpoint else {
            return .failure(.unsupportedEndpoint("nil"))
        }

        guard case let .hostPort(host, port) = endpoint else {
            return .failure(.unsupportedEndpoint(String(describing: endpoint)))
        }

        return .success(
            SSHSocketEndpoint(
                host: self.describe(host),
                port: port.rawValue
            )
        )
    }

    package static func port(_ rawPort: UInt16) throws -> NWEndpoint.Port {
        if rawPort == 0 {
            return .any
        }

        guard let port = NWEndpoint.Port(rawValue: rawPort) else {
            throw SSHTransportError.invalidPort(rawPort)
        }
        return port
    }

    private static func describe(_ host: NWEndpoint.Host) -> String {
        switch host {
        case let .name(name, _):
            name
        case let .ipv4(address):
            address.debugDescription
        case let .ipv6(address):
            address.debugDescription
        @unknown default:
            host.debugDescription
        }
    }
}
package final class SSHTCPAsyncResult<Value: Sendable>: @unchecked Sendable {
    // Sendable invariant: every mutable field below is accessed only while `lock` is held.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var continuationWaiterID: UInt64?
    private var cancelledWaiterIDs: Set<UInt64> = []
    private var result: Result<Value, Error>?
    private var didResume = false
    private var nextWaiterID: UInt64 = 0

    package init() {
    }

    package func value() async throws -> Value {
        let waiterID = self.allocateWaiterID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.install(continuation, waiterID: waiterID)
            }
        } onCancel: {
            self.cancelWaiter(waiterID)
        }
    }

    package func install(_ continuation: CheckedContinuation<Value, Error>) {
        self.install(continuation, waiterID: self.allocateWaiterID())
    }

    private func install(
        _ continuation: CheckedContinuation<Value, Error>,
        waiterID: UInt64
    ) {
        let result: Result<Value, Error>?
        let shouldCancel: Bool

        self.lock.lock()
        if self.didResume {
            result = self.result
            shouldCancel = false
        } else if self.cancelledWaiterIDs.remove(waiterID) != nil {
            result = nil
            shouldCancel = true
        } else {
            precondition(self.continuation == nil, "TCP async result already has a waiter")
            self.continuation = continuation
            self.continuationWaiterID = waiterID
            result = nil
            shouldCancel = false
        }
        self.lock.unlock()

        if shouldCancel {
            continuation.resume(throwing: CancellationError())
            return
        }

        guard let result else {
            return
        }

        continuation.resume(with: result)
    }

    @discardableResult
    package func resume(with result: Result<Value, Error>) -> Bool {
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
        self.continuationWaiterID = nil
        self.cancelledWaiterIDs.removeAll(keepingCapacity: false)
        self.lock.unlock()

        continuation?.resume(with: result)
        return true
    }

    private func allocateWaiterID() -> UInt64 {
        self.lock.lock()
        defer { self.lock.unlock() }

        let waiterID = self.nextWaiterID
        self.nextWaiterID &+= 1
        return waiterID
    }

    private func cancelWaiter(_ waiterID: UInt64) {
        let continuation: CheckedContinuation<Value, Error>?

        self.lock.lock()
        guard !self.didResume else {
            self.lock.unlock()
            return
        }

        if self.continuationWaiterID == waiterID {
            continuation = self.continuation
            self.continuation = nil
            self.continuationWaiterID = nil
        } else {
            self.cancelledWaiterIDs.insert(waiterID)
            continuation = nil
        }
        self.lock.unlock()

        continuation?.resume(throwing: CancellationError())
    }
}
