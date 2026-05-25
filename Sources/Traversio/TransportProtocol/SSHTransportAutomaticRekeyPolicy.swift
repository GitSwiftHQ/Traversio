// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHTransportAutomaticRekeyPolicy: Equatable, Sendable {
    package let outboundPacketThreshold: UInt64?
    package let inboundPacketThreshold: UInt64?
    package let idleTimeIntervalNanoseconds: UInt64?

    package static let disabled = Self(
        outboundPacketThreshold: nil,
        inboundPacketThreshold: nil,
        idleTimeIntervalNanoseconds: nil
    )

    package static let currentProfileDefault = Self(
        outboundPacketThreshold: 1_048_576,
        inboundPacketThreshold: 1_048_576,
        idleTimeIntervalNanoseconds: nil
    )

    package init(
        outboundPacketThreshold: UInt64?,
        inboundPacketThreshold: UInt64?,
        idleTimeIntervalNanoseconds: UInt64?
    ) {
        self.outboundPacketThreshold = outboundPacketThreshold
        self.inboundPacketThreshold = inboundPacketThreshold
        self.idleTimeIntervalNanoseconds = idleTimeIntervalNanoseconds
    }

    func nextTrigger(
        outboundPacketCount: UInt64,
        inboundPacketCount: UInt64,
        idleNanosecondsSinceLastActivity: UInt64? = nil
    ) -> SSHTransportAutomaticRekeyTrigger? {
        if let outboundPacketThreshold, outboundPacketCount >= outboundPacketThreshold {
            return .outboundPacketThreshold(
                currentCount: outboundPacketCount,
                threshold: outboundPacketThreshold
            )
        }

        if let inboundPacketThreshold, inboundPacketCount >= inboundPacketThreshold {
            return .inboundPacketThreshold(
                currentCount: inboundPacketCount,
                threshold: inboundPacketThreshold
            )
        }

        if let idleTimeIntervalNanoseconds,
           let idleNanosecondsSinceLastActivity,
           idleNanosecondsSinceLastActivity >= idleTimeIntervalNanoseconds {
            return .idleTimeInterval(
                currentNanoseconds: idleNanosecondsSinceLastActivity,
                thresholdNanoseconds: idleTimeIntervalNanoseconds
            )
        }

        return nil
    }
}

extension SSHTransportAutomaticRekeyPolicy {
    init(_ policy: SSHAutomaticRekeyPolicy) {
        self.init(
            outboundPacketThreshold: policy.outboundPacketThreshold,
            inboundPacketThreshold: policy.inboundPacketThreshold,
            idleTimeIntervalNanoseconds: policy.idleTimeInterval.map(Self.idleTimeIntervalNanoseconds)
        )
    }

    private static func idleTimeIntervalNanoseconds(_ idleTimeInterval: Double) -> UInt64 {
        let nanoseconds = idleTimeInterval * 1_000_000_000
        if nanoseconds >= Double(UInt64.max) {
            return UInt64.max
        }

        return max(1, UInt64(nanoseconds.rounded(.up)))
    }
}

package enum SSHTransportAutomaticRekeyTrigger: Equatable, Sendable {
    case outboundPacketThreshold(currentCount: UInt64, threshold: UInt64)
    case inboundPacketThreshold(currentCount: UInt64, threshold: UInt64)
    case idleTimeInterval(currentNanoseconds: UInt64, thresholdNanoseconds: UInt64)
}
