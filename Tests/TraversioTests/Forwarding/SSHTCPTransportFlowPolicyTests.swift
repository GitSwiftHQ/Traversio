// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Suite("TCP transport flow policy")
struct SSHTCPTransportFlowPolicyTests {
    @Test
    func automaticOrdinaryConnectionUsesModernStructuredScopeWhenAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .ordinaryConnection,
            preference: .automatic,
            modernAvailable: true
        )

        // An ordinary modern connection must never resolve to the escaped,
        // reference-release-only handle; it is served through a library-owned
        // structured scope that tears down deterministically.
        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .libraryOwnedStructuredScope)
        #expect(policy.ownershipModel != .escapedConnectionHandle)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.terminalCloseEvidence != .referenceReleaseOnly)
        #expect(policy.operationCancellationIsolation == .canIgnoreCallerCancellation)
        #expect(!policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
    }

    @Test
    func explicitModernOrdinaryConnectionUsesStructuredScopeInsteadOfEscapedHandle() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .ordinaryConnection,
            preference: .modern,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .libraryOwnedStructuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.supportsDeterministicAbort)
    }

    @Test
    func automaticScopedConnectionUsesModernStructuredScopeWhenAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .scopedConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .callerOwnedStructuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.operationCancellationIsolation == .canIgnoreCallerCancellation)
        #expect(!policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
    }

    @Test
    func automaticRouteRootUsesLegacyHandleWhenModernIsAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .routeRootConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .legacyNWConnection)
        #expect(policy.ownershipModel == .explicitCancellationHandle)
        #expect(policy.terminalCloseEvidence == .explicitCancellation)
        #expect(policy.operationCancellationIsolation == .canIgnoreCallerCancellation)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
        #expect(policy.satisfiesLongLivedRouteRootRequirements)
    }

    @Test
    func automaticStructuredRouteRootHasStructuredCloseAndReceiveIsolation() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .structuredRouteRootConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .callerOwnedStructuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
        #expect(policy.isSelectedBackendAvailable)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(policy.satisfiesLongLivedRouteRootRequirements)
    }

    @Test
    func explicitModernRouteRootUsesLibraryOwnedStructuredScope() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .routeRootConnection,
            preference: .modern,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .libraryOwnedStructuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
        #expect(policy.satisfiesLongLivedRouteRootRequirements)
    }

    @Test
    func explicitModernStructuredRouteRootKeepsStructuredCloseEvidence() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .structuredRouteRootConnection,
            preference: .modern,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .callerOwnedStructuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(!policy.needsSharedProtocolReceiveCancellationIsolation)
        #expect(policy.satisfiesLongLivedRouteRootRequirements)
    }

    @Test
    func automaticLifecycleControlledListenerUsesLegacyHandleWhenModernIsAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .lifecycleControlledListener,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .legacyNWConnection)
        #expect(policy.ownershipModel == .explicitCancellationHandle)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.requiresSharedProtocolReceiveCancellationIsolation)
        #expect(policy.supportsSharedProtocolReceiveCancellationIsolation)
    }

    @Test
    func automaticConnectionFallsBackToLegacyWhenModernIsUnavailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .ordinaryConnection,
            preference: .automatic,
            modernAvailable: false
        )

        #expect(policy.selectedBackend == .legacyNWConnection)
        #expect(policy.ownershipModel == .explicitCancellationHandle)
        #expect(policy.isSelectedBackendAvailable)
    }

    @Test
    func explicitModernRecordsBackendAvailabilitySeparatelyFromSelection() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .scopedConnection,
            preference: .modern,
            modernAvailable: false
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(!policy.isSelectedBackendAvailable)
    }
}
