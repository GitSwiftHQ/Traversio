// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHMPInt: Equatable, Sendable {
    static let zero = SSHMPInt(encodedBytes: [])!

    let encodedBytes: [UInt8]

    var isZero: Bool {
        self.encodedBytes.isEmpty
    }

    init?(encodedBytes: [UInt8]) {
        guard Self.isCanonicalEncoding(encodedBytes) else {
            return nil
        }

        self.encodedBytes = encodedBytes
    }

    init(unsignedMagnitude bytes: [UInt8]) {
        let magnitude = Array(bytes.drop { $0 == 0 })

        guard let firstByte = magnitude.first else {
            self = .zero
            return
        }

        if firstByte & 0x80 == 0x80 {
            self.encodedBytes = [0] + magnitude
        } else {
            self.encodedBytes = magnitude
        }
    }

    private static func isCanonicalEncoding(_ bytes: [UInt8]) -> Bool {
        guard !bytes.isEmpty else {
            return true
        }

        if bytes == [0] {
            return false
        }

        if bytes.count > 1 {
            let firstByte = bytes[0]
            let secondByte = bytes[1]

            if firstByte == 0x00 && secondByte & 0x80 == 0 {
                return false
            }

            if firstByte == 0xff && secondByte & 0x80 == 0x80 {
                return false
            }
        }

        return true
    }
}
