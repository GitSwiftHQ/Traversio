// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHTCPTransportBackendSelection: Equatable, Sendable {
    case modernNetworkConnection
    case legacyNWConnection
}

package enum SSHTCPTransportFlowRole: Equatable, Sendable {
    case ordinaryConnection
    case routeRootConnection
    case structuredRouteRootConnection
    case scopedConnection
    case listener
    case lifecycleControlledListener
}

package enum SSHTCPTransportOwnershipModel: Equatable, Sendable {
    case explicitCancellationHandle
    case callerOwnedStructuredScope
    case libraryOwnedStructuredScope
    case escapedConnectionHandle
}

package enum SSHTCPTransportTerminalCloseEvidence: Equatable, Sendable {
    case explicitCancellation
    case structuredScopeExit
    case referenceReleaseOnly
}

package enum SSHTCPTransportOperationCancellationIsolation: Equatable, Sendable {
    case canIgnoreCallerCancellation
    case callerCancellationMayCancelUnderlyingOperation
}

package struct SSHTCPTransportFlowPolicy: Equatable, Sendable {
    package let role: SSHTCPTransportFlowRole
    package let preference: SSHTCPTransportBackendPreference
    package let selectedBackend: SSHTCPTransportBackendSelection
    package let ownershipModel: SSHTCPTransportOwnershipModel
    package let terminalCloseEvidence: SSHTCPTransportTerminalCloseEvidence
    package let operationCancellationIsolation: SSHTCPTransportOperationCancellationIsolation
    package let requiresDeterministicAbort: Bool
    package let supportsDeterministicAbort: Bool
    package let requiresSharedProtocolReceiveCancellationIsolation: Bool
    package let supportsSharedProtocolReceiveCancellationIsolation: Bool
    package let isSelectedBackendAvailable: Bool

    package var needsStructuredRouteOwnerForDeterministicAbort: Bool {
        self.requiresDeterministicAbort && !self.supportsDeterministicAbort
    }

    package var needsSharedProtocolReceiveCancellationIsolation: Bool {
        self.requiresSharedProtocolReceiveCancellationIsolation
            && !self.supportsSharedProtocolReceiveCancellationIsolation
    }

    package var satisfiesLongLivedRouteRootRequirements: Bool {
        !self.needsStructuredRouteOwnerForDeterministicAbort
            && !self.needsSharedProtocolReceiveCancellationIsolation
    }

    package static func resolveCurrentPlatform(
        role: SSHTCPTransportFlowRole,
        preference: SSHTCPTransportBackendPreference
    ) -> Self {
        Self.resolve(
            role: role,
            preference: preference,
            modernAvailable: Self.isModernNetworkConnectionAvailable
        )
    }

    package static func resolve(
        role: SSHTCPTransportFlowRole,
        preference: SSHTCPTransportBackendPreference,
        modernAvailable: Bool
    ) -> Self {
        let selectedBackend = self.selectedBackend(
            role: role,
            preference: preference,
            modernAvailable: modernAvailable
        )
        let ownershipModel = self.ownershipModel(
            role: role,
            selectedBackend: selectedBackend
        )
        let terminalCloseEvidence = self.terminalCloseEvidence(
            ownershipModel: ownershipModel
        )
        let operationCancellationIsolation = self.operationCancellationIsolation(
            selectedBackend: selectedBackend
        )
        let requiresDeterministicAbort = self.requiresDeterministicAbort(role: role)
        let supportsDeterministicAbort = self.supportsDeterministicAbort(
            terminalCloseEvidence: terminalCloseEvidence
        )
        let requiresSharedProtocolReceiveCancellationIsolation =
            self.requiresSharedProtocolReceiveCancellationIsolation(role: role)
        let supportsSharedProtocolReceiveCancellationIsolation =
            self.supportsSharedProtocolReceiveCancellationIsolation(
                isolation: operationCancellationIsolation
            )

        return Self(
            role: role,
            preference: preference,
            selectedBackend: selectedBackend,
            ownershipModel: ownershipModel,
            terminalCloseEvidence: terminalCloseEvidence,
            operationCancellationIsolation: operationCancellationIsolation,
            requiresDeterministicAbort: requiresDeterministicAbort,
            supportsDeterministicAbort: supportsDeterministicAbort,
            requiresSharedProtocolReceiveCancellationIsolation: requiresSharedProtocolReceiveCancellationIsolation,
            supportsSharedProtocolReceiveCancellationIsolation: supportsSharedProtocolReceiveCancellationIsolation,
            isSelectedBackendAvailable: selectedBackend == .legacyNWConnection || modernAvailable
        )
    }

    package static var isModernNetworkConnectionAvailable: Bool {
        if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            return true
        }

        return false
    }

    private static func selectedBackend(
        role: SSHTCPTransportFlowRole,
        preference: SSHTCPTransportBackendPreference,
        modernAvailable: Bool
    ) -> SSHTCPTransportBackendSelection {
        switch preference {
        case .legacy:
            return .legacyNWConnection
        case .modern:
            return .modernNetworkConnection
        case .automatic:
            switch role {
            case .routeRootConnection, .lifecycleControlledListener:
                return .legacyNWConnection
            case .ordinaryConnection, .structuredRouteRootConnection, .scopedConnection, .listener:
                return modernAvailable ? .modernNetworkConnection : .legacyNWConnection
            }
        }
    }

    private static func ownershipModel(
        role: SSHTCPTransportFlowRole,
        selectedBackend: SSHTCPTransportBackendSelection
    ) -> SSHTCPTransportOwnershipModel {
        switch selectedBackend {
        case .legacyNWConnection:
            return .explicitCancellationHandle
        case .modernNetworkConnection:
            switch role {
            case .routeRootConnection:
                return .libraryOwnedStructuredScope
            case .structuredRouteRootConnection, .scopedConnection, .listener, .lifecycleControlledListener:
                return .callerOwnedStructuredScope
            case .ordinaryConnection:
                return .escapedConnectionHandle
            }
        }
    }

    private static func terminalCloseEvidence(
        ownershipModel: SSHTCPTransportOwnershipModel
    ) -> SSHTCPTransportTerminalCloseEvidence {
        switch ownershipModel {
        case .explicitCancellationHandle:
            .explicitCancellation
        case .callerOwnedStructuredScope, .libraryOwnedStructuredScope:
            .structuredScopeExit
        case .escapedConnectionHandle:
            .referenceReleaseOnly
        }
    }

    private static func operationCancellationIsolation(
        selectedBackend: SSHTCPTransportBackendSelection
    ) -> SSHTCPTransportOperationCancellationIsolation {
        switch selectedBackend {
        case .legacyNWConnection, .modernNetworkConnection:
            .canIgnoreCallerCancellation
        }
    }

    private static func requiresDeterministicAbort(
        role: SSHTCPTransportFlowRole
    ) -> Bool {
        switch role {
        case .routeRootConnection, .structuredRouteRootConnection, .lifecycleControlledListener:
            true
        case .ordinaryConnection, .scopedConnection, .listener:
            false
        }
    }

    private static func requiresSharedProtocolReceiveCancellationIsolation(
        role: SSHTCPTransportFlowRole
    ) -> Bool {
        switch role {
        case .routeRootConnection, .structuredRouteRootConnection:
            true
        case .ordinaryConnection, .scopedConnection, .listener, .lifecycleControlledListener:
            false
        }
    }

    private static func supportsDeterministicAbort(
        terminalCloseEvidence: SSHTCPTransportTerminalCloseEvidence
    ) -> Bool {
        switch terminalCloseEvidence {
        case .explicitCancellation, .structuredScopeExit:
            true
        case .referenceReleaseOnly:
            false
        }
    }

    private static func supportsSharedProtocolReceiveCancellationIsolation(
        isolation: SSHTCPTransportOperationCancellationIsolation
    ) -> Bool {
        switch isolation {
        case .canIgnoreCallerCancellation:
            true
        case .callerCancellationMayCancelUnderlyingOperation:
            false
        }
    }
}
