// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Storage interface used by `SSHHostKeyPolicy.trustOnFirstUse(...)`.
///
/// Implement this in an app-owned store when host keys should be persisted
/// outside Traversio.
public protocol SSHHostKeyTrustStore: Sendable {
    /// Returns the stored host key for an endpoint, or `nil` if this is the
    /// first observed key.
    func lookupHostKey(
        endpointHost: String,
        endpointPort: UInt16
    ) async throws -> SSHTrustedHostKey?

    /// Stores a newly trusted host key.
    func storeHostKey(_ request: SSHHostKeyStoreRequest) async throws

    /// Decides what to do when the received key differs from the stored key.
    func decisionForChangedHostKey(
        _ request: SSHHostKeyChangeRequest
    ) async throws -> SSHHostKeyChangeDecision
}
public extension SSHHostKeyTrustStore {
    func decisionForChangedHostKey(
        _ request: SSHHostKeyChangeRequest
    ) async throws -> SSHHostKeyChangeDecision {
        .reject
    }
}
