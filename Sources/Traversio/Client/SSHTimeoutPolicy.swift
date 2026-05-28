// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch
import Foundation

/// Timeout configuration for connection setup and protocol responses.
///
/// The default profile bounds connection setup but leaves per-response timeouts
/// disabled unless the caller opts in.
public struct SSHTimeoutPolicy: Equatable, Sendable {
    /// Connection Setup time interval.
    public let connectionSetupTimeInterval: TimeInterval?
    /// Host-key trust decision time interval.
    public let hostKeyTrustTimeInterval: TimeInterval?
    /// Response time interval.
    public let responseTimeInterval: TimeInterval?

    /// Default Connection Setup time interval.
    public static let defaultConnectionSetupTimeInterval: TimeInterval = 30
    /// Default host-key trust decision time interval.
    public static let defaultHostKeyTrustTimeInterval: TimeInterval = 120

    /// Current Profile Default.
    public static let currentProfileDefault = Self()

    /// Disabled.
    public static let disabled = Self(
        connectionSetupTimeInterval: nil,
        hostKeyTrustTimeInterval: nil,
        responseTimeInterval: nil
    )

    /// Creates an SSHTimeoutPolicy.
    public init(
        connectionSetupTimeInterval: TimeInterval? = Self.defaultConnectionSetupTimeInterval,
        hostKeyTrustTimeInterval: TimeInterval? = Self.defaultHostKeyTrustTimeInterval,
        responseTimeInterval: TimeInterval? = nil
    ) {
        precondition(
            Self.isValid(connectionSetupTimeInterval),
            "connectionSetupTimeInterval must be nil or a finite value greater than zero"
        )
        precondition(
            Self.isValid(hostKeyTrustTimeInterval),
            "hostKeyTrustTimeInterval must be nil or a finite value greater than zero"
        )
        precondition(
            Self.isValid(responseTimeInterval),
            "responseTimeInterval must be nil or a finite value greater than zero"
        )

        self.connectionSetupTimeInterval = connectionSetupTimeInterval
        self.hostKeyTrustTimeInterval = hostKeyTrustTimeInterval
        self.responseTimeInterval = responseTimeInterval
    }

    private static func isValid(_ value: TimeInterval?) -> Bool {
        guard let value else {
            return true
        }

        return value.isFinite && value > 0
    }
}

enum SSHTimeoutError: Error, Equatable, Sendable {
    case connectionSetup(durationNanoseconds: UInt64)
    case hostKeyTrust(durationNanoseconds: UInt64)
    case keepaliveReply(durationNanoseconds: UInt64)
    case channelOpenResponse(durationNanoseconds: UInt64)
    case channelRequestReply(requestType: String, durationNanoseconds: UInt64)
    case globalRequestReply(requestType: String, durationNanoseconds: UInt64)
    case sftpResponse(durationNanoseconds: UInt64)

    var message: String {
        switch self {
        case let .connectionSetup(durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for SSH connection setup to finish."
        case let .hostKeyTrust(durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for host-key trust confirmation."
        case let .keepaliveReply(durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for an SSH keepalive reply."
        case let .channelOpenResponse(durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for a channel open response."
        case let .channelRequestReply(requestType, durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for the \(requestType) channel request reply."
        case let .globalRequestReply(requestType, durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for the \(requestType) global request reply."
        case let .sftpResponse(durationNanoseconds):
            return
                "Timed out after \(formattedTimeoutInterval(durationNanoseconds)) while waiting for an SFTP response."
        }
    }

    var requestType: String? {
        switch self {
        case .keepaliveReply:
            return "keepalive"
        case let .channelRequestReply(requestType, _),
            let .globalRequestReply(requestType, _):
            return requestType
        default:
            return nil
        }
    }
}

struct SSHInternalTimeoutPolicy: Equatable, Sendable {
    let connectionSetupTimeoutNanoseconds: UInt64?
    let hostKeyTrustTimeoutNanoseconds: UInt64?
    let responseTimeoutNanoseconds: UInt64?

    init(_ policy: SSHTimeoutPolicy) {
        self.connectionSetupTimeoutNanoseconds = policy.connectionSetupTimeInterval.map(
            Self.nanoseconds
        )
        self.hostKeyTrustTimeoutNanoseconds = policy.hostKeyTrustTimeInterval.map(
            Self.nanoseconds
        )
        self.responseTimeoutNanoseconds = policy.responseTimeInterval.map(Self.nanoseconds)
    }

    private static func nanoseconds(_ timeInterval: TimeInterval) -> UInt64 {
        let nanoseconds = timeInterval * 1_000_000_000
        if nanoseconds >= Double(UInt64.max) {
            return UInt64.max
        }

        return max(1, UInt64(nanoseconds.rounded(.up)))
    }
}

actor SSHConnectionSetupTimeoutBudget {
    private let timeoutNanoseconds: UInt64?
    private var consumedNanoseconds: UInt64 = 0

    init(timeoutNanoseconds: UInt64?) {
        self.timeoutNanoseconds = timeoutNanoseconds
    }

    func withTimeout<Result: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        guard let timeoutNanoseconds else {
            return try await operation()
        }

        let remainingNanoseconds = try self.remainingNanoseconds(
            timeoutNanoseconds: timeoutNanoseconds
        )
        let startedAt = DispatchTime.now().uptimeNanoseconds
        do {
            let result = try await withOptionalTimeout(
                nanoseconds: remainingNanoseconds,
                timeoutError: SSHTimeoutError.connectionSetup(
                    durationNanoseconds: timeoutNanoseconds
                )
            ) {
                try await operation()
            }
            self.recordElapsed(since: startedAt, timeoutNanoseconds: timeoutNanoseconds)
            return result
        } catch {
            self.recordElapsed(since: startedAt, timeoutNanoseconds: timeoutNanoseconds)
            throw error
        }
    }

    private func remainingNanoseconds(timeoutNanoseconds: UInt64) throws -> UInt64 {
        guard self.consumedNanoseconds < timeoutNanoseconds else {
            throw SSHTimeoutError.connectionSetup(durationNanoseconds: timeoutNanoseconds)
        }

        return timeoutNanoseconds - self.consumedNanoseconds
    }

    private func recordElapsed(
        since startedAt: UInt64,
        timeoutNanoseconds: UInt64
    ) {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsedNanoseconds = now >= startedAt ? now - startedAt : 0
        let availableNanoseconds = timeoutNanoseconds - self.consumedNanoseconds
        self.consumedNanoseconds += min(elapsedNanoseconds, availableNanoseconds)
    }
}

func withOptionalTimeout<Result: Sendable>(
    nanoseconds: UInt64?,
    timeoutError: @autoclosure @escaping @Sendable () -> SSHTimeoutError,
    onTimeout: @escaping @Sendable () async -> Void = {},
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    guard let nanoseconds else {
        return try await operation()
    }

    return try await withThrowingTaskGroup(of: Result.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            await onTimeout()
            throw timeoutError()
        }

        defer {
            group.cancelAll()
        }

        guard let result = try await group.next() else {
            throw timeoutError()
        }
        return result
    }
}

private func formattedTimeoutInterval(_ nanoseconds: UInt64) -> String {
    let seconds = Double(nanoseconds) / 1_000_000_000
    if seconds.rounded() == seconds {
        return "\(Int(seconds))s"
    }

    var rendered = String(format: "%.3f", seconds)
    while rendered.last == "0" {
        rendered.removeLast()
    }
    if rendered.last == "." {
        rendered.removeLast()
    }
    return "\(rendered)s"
}
