// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

struct SSHWireReader: Sendable {
    private let bytes: [UInt8]

    private(set) var readIndex: Int

    init(bytes: [UInt8]) {
        self.bytes = bytes
        self.readIndex = 0
    }

    var remainingByteCount: Int {
        self.bytes.count - self.readIndex
    }

    var isAtEnd: Bool {
        self.readIndex == self.bytes.count
    }

    mutating func readByte() throws -> UInt8 {
        try self.requireBytes(1)

        let value = self.bytes[self.readIndex]
        self.readIndex += 1
        return value
    }

    mutating func readBoolean() throws -> Bool {
        switch try self.readByte() {
        case 0:
            return false
        case 1:
            return true
        case let value:
            throw SSHWireError.invalidBoolean(value)
        }
    }

    mutating func readUInt32() throws -> UInt32 {
        let rawBytes = try self.readRawBytes(count: 4)

        return rawBytes.reduce(into: UInt32.zero) { value, byte in
            value = (value << 8) | UInt32(byte)
        }
    }

    mutating func readUInt64() throws -> UInt64 {
        let rawBytes = try self.readRawBytes(count: 8)

        return rawBytes.reduce(into: UInt64.zero) { value, byte in
            value = (value << 8) | UInt64(byte)
        }
    }

    mutating func readString() throws -> [UInt8] {
        let length = try Int(self.readUInt32())
        return try self.readRawBytes(count: length)
    }

    mutating func readUTF8String() throws -> String {
        let payload = try self.readString()

        guard let value = String(bytes: payload, encoding: .utf8) else {
            throw SSHWireError.invalidUTF8String
        }

        return value
    }

    mutating func readNameList() throws -> [String] {
        let payload = try self.readString()

        guard let rawValue = String(bytes: payload, encoding: .utf8) else {
            throw SSHWireError.invalidUTF8String
        }

        guard !rawValue.isEmpty else {
            return []
        }

        let components = rawValue.split(separator: ",", omittingEmptySubsequences: false).map(String.init)

        guard !components.isEmpty else {
            return []
        }

        guard components.allSatisfy(Self.isValidNameListEntry(_:)) else {
            throw SSHWireError.invalidNameList
        }

        return components
    }

    mutating func readMPInt() throws -> SSHMPInt {
        let payload = try self.readString()

        guard let value = SSHMPInt(encodedBytes: payload) else {
            throw SSHWireError.invalidMPInt
        }

        return value
    }

    mutating func readRawBytes(count: Int) throws -> [UInt8] {
        try self.requireBytes(count)

        let endIndex = self.readIndex + count
        let value = Array(self.bytes[self.readIndex..<endIndex])
        self.readIndex = endIndex
        return value
    }

    private mutating func requireBytes(_ count: Int) throws {
        guard self.remainingByteCount >= count else {
            throw SSHWireError.insufficientBytes(
                expected: count,
                remaining: self.remainingByteCount
            )
        }
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
