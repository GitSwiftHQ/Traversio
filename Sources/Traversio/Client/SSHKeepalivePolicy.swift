// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Background keepalive configuration for an established SSH connection.
///
/// Keepalives are disabled by default. Enable them when an app needs faster
/// detection of broken idle connections.
public struct SSHKeepalivePolicy: Equatable, Sendable {
    /// Interval.
    public let interval: TimeInterval?

    /// Disabled.
    public static let disabled = Self(interval: nil)

    /// Creates an SSHKeepalivePolicy.
    public init(interval: TimeInterval?) {
        precondition(
            Self.isValid(interval),
            "interval must be nil or a finite value greater than zero"
        )
        self.interval = interval
    }

    private static func isValid(_ value: TimeInterval?) -> Bool {
        guard let value else {
            return true
        }

        return value.isFinite && value > 0
    }
}
