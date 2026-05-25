// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Progress value emitted by high-level SFTP transfers.
public struct SSHSFTPTransferProgress: Equatable, Sendable {
    /// Transfer direction for a progress value.
    public enum Operation: Equatable, Sendable {
        /// Read.
        case read
        /// Write.
        case write
    }
/// Operation.

    /// Operation.
    public let operation: Operation
    /// Bytes Transferred.
    public let bytesTransferred: UInt64
    /// Total Bytes.
    public let totalBytes: UInt64?
    /// Creates an SSHSFTPTransferProgress.

    public init(
        operation: Operation,
        bytesTransferred: UInt64,
        totalBytes: UInt64? = nil
    ) {
        self.operation = operation
        self.bytesTransferred = bytesTransferred
        self.totalBytes = totalBytes
    }

    /// Fraction Completed.
    public var fractionCompleted: Double? {
        guard let totalBytes, totalBytes > 0 else {
            return nil
        }

        return min(Double(self.bytesTransferred) / Double(totalBytes), 1)
    }
}

/// Async callback used to report high-level SFTP transfer progress.
public typealias SSHSFTPTransferProgressHandler = @Sendable (SSHSFTPTransferProgress) async -> Void

/// Return `false` to stop a high-level SFTP transfer with `CancellationError`.
public typealias SSHSFTPTransferContinuationHandler = @Sendable () async -> Bool

extension SFTPClient {
    func checkTransferContinuation(
        _ shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws {
        try Task.checkCancellation()

        if let shouldContinue, await shouldContinue() == false {
            throw CancellationError()
        }
    }
}
