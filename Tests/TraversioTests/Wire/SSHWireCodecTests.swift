// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func writerSerializesSSHPrimitivesUsingNetworkByteOrder() throws {
    var writer = SSHWireWriter()
    writer.write(byte: 0x05)
    writer.write(boolean: true)
    writer.write(boolean: false)
    writer.write(uint32: 0x01020304)
    writer.write(uint64: 0x0102030405060708)
    writer.write(string: [0xde, 0xad, 0xbe, 0xef])
    writer.write(utf8: "hi")
    try writer.write(nameList: ["a", "b"])
    writer.write(mpint: SSHMPInt(unsignedMagnitude: [0x80]))

    #expect(
        writer.bytes == [
            0x05,
            0x01,
            0x00,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x02, 0x68, 0x69,
            0x00, 0x00, 0x00, 0x03, 0x61, 0x2c, 0x62,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x80,
        ]
    )
}

@Test
func readerDecodesSSHPrimitivesAndConsumesAllBytes() throws {
    var reader = SSHWireReader(
        bytes: [
            0x05,
            0x01,
            0x00,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
            0x00, 0x00, 0x00, 0x02, 0x68, 0x69,
            0x00, 0x00, 0x00, 0x03, 0x61, 0x2c, 0x62,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x80,
        ]
    )

    #expect(try reader.readByte() == 0x05)
    #expect(try reader.readBoolean())
    #expect(try !reader.readBoolean())
    #expect(try reader.readUInt32() == 0x01020304)
    #expect(try reader.readUInt64() == 0x0102030405060708)
    #expect(try reader.readString() == [0xde, 0xad, 0xbe, 0xef])
    #expect(try reader.readUTF8String() == "hi")
    #expect(try reader.readNameList() == ["a", "b"])
    #expect(try reader.readMPInt() == SSHMPInt(unsignedMagnitude: [0x80]))
    #expect(reader.isAtEnd)
    #expect(reader.remainingByteCount == 0)
}

@Test
func readBooleanRejectsNonCanonicalValues() throws {
    var reader = SSHWireReader(bytes: [0x02])

    do {
        _ = try reader.readBoolean()
        Issue.record("Expected invalid boolean error")
    } catch {
        #expect(error as? SSHWireError == .invalidBoolean(0x02))
    }
}

@Test
func readStringRejectsTruncatedPayloads() throws {
    var reader = SSHWireReader(bytes: [0x00, 0x00, 0x00, 0x04, 0xaa, 0xbb])

    do {
        _ = try reader.readString()
        Issue.record("Expected insufficient-bytes error")
    } catch {
        #expect(error as? SSHWireError == .insufficientBytes(expected: 4, remaining: 2))
    }
}

@Test
func readUTF8StringRejectsInvalidPayload() throws {
    var reader = SSHWireReader(bytes: [0x00, 0x00, 0x00, 0x02, 0xc3, 0x28])

    do {
        _ = try reader.readUTF8String()
        Issue.record("Expected invalid UTF-8 error")
    } catch {
        #expect(error as? SSHWireError == .invalidUTF8String)
    }
}

@Test
func nameListsRejectEmptyEntriesOnReadAndWrite() throws {
    var reader = SSHWireReader(bytes: [0x00, 0x00, 0x00, 0x04, 0x61, 0x2c, 0x2c, 0x62])

    do {
        _ = try reader.readNameList()
        Issue.record("Expected invalid name-list error")
    } catch {
        #expect(error as? SSHWireError == .invalidNameList)
    }

    var writer = SSHWireWriter()

    do {
        try writer.write(nameList: ["valid", ""])
        Issue.record("Expected invalid name-list error")
    } catch {
        #expect(error as? SSHWireError == .invalidNameList)
    }
}

@Test
func mpIntsRejectNonCanonicalZeroEncoding() throws {
    var reader = SSHWireReader(bytes: [0x00, 0x00, 0x00, 0x01, 0x00])

    do {
        _ = try reader.readMPInt()
        Issue.record("Expected invalid mpint error")
    } catch {
        #expect(error as? SSHWireError == .invalidMPInt)
    }
}

@Test
func mpIntUnsignedMagnitudeAddsSignPaddingWhenNeeded() {
    #expect(SSHMPInt(unsignedMagnitude: []).encodedBytes == [])
    #expect(SSHMPInt(unsignedMagnitude: [0x7f]).encodedBytes == [0x7f])
    #expect(SSHMPInt(unsignedMagnitude: [0x80]).encodedBytes == [0x00, 0x80])
    #expect(SSHMPInt(unsignedMagnitude: [0x00, 0x00, 0x01]).encodedBytes == [0x01])
}
