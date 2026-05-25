// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

struct SSHWireWriter: Sendable {
    private(set) var bytes: [UInt8]

    init(capacity: Int = 0) {
        self.bytes = []
        self.bytes.reserveCapacity(capacity)
    }

    mutating func write(byte value: UInt8) {
        self.bytes.append(value)
    }

    mutating func write(boolean value: Bool) {
        self.write(byte: value ? 1 : 0)
    }

    mutating func write(uint32 value: UInt32) {
        self.bytes.append(UInt8((value >> 24) & 0xff))
        self.bytes.append(UInt8((value >> 16) & 0xff))
        self.bytes.append(UInt8((value >> 8) & 0xff))
        self.bytes.append(UInt8(value & 0xff))
    }

    mutating func write(uint64 value: UInt64) {
        self.bytes.append(UInt8((value >> 56) & 0xff))
        self.bytes.append(UInt8((value >> 48) & 0xff))
        self.bytes.append(UInt8((value >> 40) & 0xff))
        self.bytes.append(UInt8((value >> 32) & 0xff))
        self.bytes.append(UInt8((value >> 24) & 0xff))
        self.bytes.append(UInt8((value >> 16) & 0xff))
        self.bytes.append(UInt8((value >> 8) & 0xff))
        self.bytes.append(UInt8(value & 0xff))
    }

    mutating func write(string value: [UInt8]) {
        self.write(uint32: UInt32(value.count))
        self.bytes.append(contentsOf: value)
    }

    mutating func write(rawBytes value: [UInt8]) {
        self.bytes.append(contentsOf: value)
    }

    mutating func write(utf8 value: String) {
        self.write(string: Array(value.utf8))
    }

    mutating func write(nameList values: [String]) throws {
        guard values.allSatisfy(Self.isValidNameListEntry(_:)) else {
            throw SSHWireError.invalidNameList
        }

        self.write(utf8: values.joined(separator: ","))
    }

    mutating func write(mpint value: SSHMPInt) {
        self.write(string: value.encodedBytes)
    }

    private static func isValidNameListEntry(_ value: String) -> Bool {
        guard !value.isEmpty else {
            return false
        }

        return value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && scalar.value >= 0x21 && scalar.value <= 0x7e && scalar.value != 0x2c
        }
    }
}
