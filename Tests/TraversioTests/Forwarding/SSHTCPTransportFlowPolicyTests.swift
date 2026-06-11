// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Suite("TCP transport flow policy")
struct SSHTCPTransportFlowPolicyTests {
    @Test
    func automaticOrdinaryConnectionUsesModernWhenAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .ordinaryConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .escapedConnectionHandle)
        #expect(policy.terminalCloseEvidence == .referenceReleaseOnly)
        #expect(!policy.requiresDeterministicAbort)
        #expect(!policy.supportsDeterministicAbort)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
    }

    @Test
    func automaticScopedConnectionUsesModernStructuredScopeWhenAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .scopedConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .structuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(!policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
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
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
    }

    @Test
    func automaticStructuredRouteRootUsesModernScopeWhenModernIsAvailable() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .structuredRouteRootConnection,
            preference: .automatic,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .structuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(policy.isSelectedBackendAvailable)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
    }

    @Test
    func explicitModernRouteRootRecordsMissingDeterministicAbortOwner() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .routeRootConnection,
            preference: .modern,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .escapedConnectionHandle)
        #expect(policy.terminalCloseEvidence == .referenceReleaseOnly)
        #expect(policy.requiresDeterministicAbort)
        #expect(!policy.supportsDeterministicAbort)
        #expect(policy.needsStructuredRouteOwnerForDeterministicAbort)
    }

    @Test
    func explicitModernStructuredRouteRootKeepsStructuredCloseEvidence() {
        let policy = SSHTCPTransportFlowPolicy.resolve(
            role: .structuredRouteRootConnection,
            preference: .modern,
            modernAvailable: true
        )

        #expect(policy.selectedBackend == .modernNetworkConnection)
        #expect(policy.ownershipModel == .structuredScope)
        #expect(policy.terminalCloseEvidence == .structuredScopeExit)
        #expect(policy.requiresDeterministicAbort)
        #expect(policy.supportsDeterministicAbort)
        #expect(!policy.needsStructuredRouteOwnerForDeterministicAbort)
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
