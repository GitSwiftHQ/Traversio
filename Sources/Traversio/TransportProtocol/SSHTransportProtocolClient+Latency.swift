// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch

extension SSHTransportProtocolClient {
    func currentLatency() -> SSHConnectionLatency? {
        self.latestLatency
    }

    func latencyMeasurementStartNanoseconds() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }

    func recordLatencyMeasurement(
        startedAt startNanoseconds: UInt64,
        source: SSHConnectionLatencySource,
        endedAt endNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        let roundTripTimeNanoseconds = endNanoseconds >= startNanoseconds
            ? endNanoseconds - startNanoseconds
            : 0
        self.latestLatency = SSHConnectionLatency(
            roundTripTimeNanoseconds: roundTripTimeNanoseconds,
            measuredAtUptimeNanoseconds: endNanoseconds,
            source: source
        )
    }
}
