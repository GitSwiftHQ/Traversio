// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

enum SSHForwardingCleanup {
    static func performIgnoringCallerCancellation<Result: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        let task = Task {
            try await operation()
        }
        return try await task.value
    }

    static func performIgnoringCallerCancellation(
        _ operation: @escaping @Sendable () async -> Void
    ) async {
        let task = Task {
            await operation()
        }
        await task.value
    }
}
