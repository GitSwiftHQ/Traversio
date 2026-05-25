// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHTransportKeepalivePolicy: Equatable, Sendable {
    package let intervalNanoseconds: UInt64?
    package let responseTimeoutNanoseconds: UInt64?

    package static let disabled = Self(
        intervalNanoseconds: nil,
        responseTimeoutNanoseconds: nil
    )

    package init(
        intervalNanoseconds: UInt64?,
        responseTimeoutNanoseconds: UInt64?
    ) {
        self.intervalNanoseconds = intervalNanoseconds
        self.responseTimeoutNanoseconds = responseTimeoutNanoseconds
    }
}

extension SSHTransportKeepalivePolicy {
    init(
        _ policy: SSHKeepalivePolicy,
        defaultResponseTimeoutNanoseconds: UInt64?
    ) {
        let intervalNanoseconds = policy.interval.map(Self.nanoseconds)
        let responseTimeoutNanoseconds = intervalNanoseconds.map { intervalNanoseconds in
            if let defaultResponseTimeoutNanoseconds {
                return min(defaultResponseTimeoutNanoseconds, intervalNanoseconds)
            }
            return intervalNanoseconds
        }

        self.init(
            intervalNanoseconds: intervalNanoseconds,
            responseTimeoutNanoseconds: responseTimeoutNanoseconds
        )
    }

    private static func nanoseconds(_ interval: Double) -> UInt64 {
        let nanoseconds = interval * 1_000_000_000
        if nanoseconds >= Double(UInt64.max) {
            return UInt64.max
        }

        return max(1, UInt64(nanoseconds.rounded(.up)))
    }
}
