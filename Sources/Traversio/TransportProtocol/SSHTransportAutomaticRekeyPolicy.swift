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

    /// Hard, non-disable-able ceiling on the number of packets that may be protected under a
    /// single set of keys when the negotiated cipher derives its nonce solely from the 32-bit
    /// packet sequence number (currently only `chacha20-poly1305@openssh.com`).
    ///
    /// That cipher's keystream is a function of (key, sequence-number). The sequence counters are
    /// `UInt32` and wrap at 2^32, so protecting 2^32 packets under one key reuses a nonce and
    /// therefore the keystream — a catastrophic, key-recovering failure. This ceiling is enforced
    /// independently of (and regardless of) the configured `SSHTransportAutomaticRekeyPolicy`,
    /// including `.disabled`, so a rekey is forced long before the counter can wrap. It is set to
    /// 2^31 — half of the wrap point — leaving a 2^31-packet safety margin that dwarfs the handful
    /// of transport packets exchanged during the rekey handshake itself. AES-GCM (independent
    /// 64-bit invocation counter) and AES-CTR (continuous cipher state) do not derive their nonce
    /// from the sequence number and are therefore not subject to this ceiling.
    package static let sequenceNumberNonceRekeyCeiling: UInt64 = 1 << 31

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
    /// A sequence-number-nonce cipher (chacha20-poly1305) reached the hard packet ceiling below
    /// which a rekey must be forced to avoid nonce/keystream reuse. Emitted regardless of the
    /// configured rekey policy; see `SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling`.
    case mandatorySequenceNumberCeiling(currentCount: UInt64, ceiling: UInt64)
}
