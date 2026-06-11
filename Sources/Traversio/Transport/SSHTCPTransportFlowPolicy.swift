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
    case structuredScope
    case escapedConnectionHandle
}

package enum SSHTCPTransportTerminalCloseEvidence: Equatable, Sendable {
    case explicitCancellation
    case structuredScopeExit
    case referenceReleaseOnly
}

package struct SSHTCPTransportFlowPolicy: Equatable, Sendable {
    package let role: SSHTCPTransportFlowRole
    package let preference: SSHTCPTransportBackendPreference
    package let selectedBackend: SSHTCPTransportBackendSelection
    package let ownershipModel: SSHTCPTransportOwnershipModel
    package let terminalCloseEvidence: SSHTCPTransportTerminalCloseEvidence
    package let requiresDeterministicAbort: Bool
    package let supportsDeterministicAbort: Bool
    package let isSelectedBackendAvailable: Bool

    package var needsStructuredRouteOwnerForDeterministicAbort: Bool {
        self.requiresDeterministicAbort && !self.supportsDeterministicAbort
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
        let requiresDeterministicAbort = self.requiresDeterministicAbort(role: role)
        let supportsDeterministicAbort = self.supportsDeterministicAbort(
            terminalCloseEvidence: terminalCloseEvidence
        )

        return Self(
            role: role,
            preference: preference,
            selectedBackend: selectedBackend,
            ownershipModel: ownershipModel,
            terminalCloseEvidence: terminalCloseEvidence,
            requiresDeterministicAbort: requiresDeterministicAbort,
            supportsDeterministicAbort: supportsDeterministicAbort,
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
            case .structuredRouteRootConnection, .scopedConnection, .listener, .lifecycleControlledListener:
                return .structuredScope
            case .ordinaryConnection, .routeRootConnection:
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
        case .structuredScope:
            .structuredScopeExit
        case .escapedConnectionHandle:
            .referenceReleaseOnly
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
}
