// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Background keepalive configuration for an established SSH connection.
///
/// A conservative keepalive is enabled by default so that a silent or
/// half-dead peer (one that stops answering but never sends FIN/RST) is
/// detected and the connection is failed promptly instead of wedging
/// in-flight operations forever. The background keepalive request/reply is the
/// liveness signal: when its reply times out the connection is torn down,
/// which unblocks every waiting operation. This is a safer mechanism than a
/// per-response timeout because it never has to cancel a shared, mid-packet
/// transport receive (which can desync the encrypted stream).
///
/// Advanced callers who knowingly want no background keepalive can opt out with
/// ``disabled``, and the interval remains fully overridable via ``init(interval:)``.
public struct SSHKeepalivePolicy: Equatable, Sendable {
    /// Interval.
    public let interval: TimeInterval?

    /// Default keepalive interval, in seconds.
    ///
    /// Matches the forwarding fallback keepalive cadence. Short-lived work
    /// never trips it, while an idle-but-dead peer is detected within roughly
    /// one to two intervals. The keepalive reply timeout is derived from this
    /// interval (see `SSHTransportKeepalivePolicy`).
    public static let defaultInterval: TimeInterval = 15

    /// Current Profile Default.
    ///
    /// Enables the conservative liveness keepalive described above.
    public static let currentProfileDefault = Self(interval: defaultInterval)

    /// Disabled.
    ///
    /// Explicit opt-out for advanced callers that never want a background
    /// keepalive. A dead peer will not be detected by this library while
    /// disabled.
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
