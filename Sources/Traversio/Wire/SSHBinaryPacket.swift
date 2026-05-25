// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHBinaryPacket: Equatable, Sendable {
    let payload: [UInt8]
    let padding: [UInt8]

    var packetLength: UInt32 {
        UInt32(1 + self.payload.count + self.padding.count)
    }
}
