// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func binaryPacketSerializerComputesDeterministicPadding() throws {
    let serializer = SSHBinaryPacketSerializer(paddingByte: 0xaa)
    let bytes = try serializer.serialize(payload: [0x15, 0x16, 0x17])

    #expect(
        bytes == [
            0x00, 0x00, 0x00, 0x0c,
            0x08,
            0x15, 0x16, 0x17,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ]
    )
}

@Test
func binaryPacketParserRoundTripsChunkedPackets() throws {
    let serializer = SSHBinaryPacketSerializer(paddingByte: 0x55)
    let bytes = try serializer.serialize(payload: [0x01, 0x02, 0x03, 0x04, 0x05])

    var parser = SSHBinaryPacketParser()
    parser.append(bytes: Array(bytes.prefix(6)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(6)))
    let parsedPacket = try parser.nextPacket()
    let packet = try #require(parsedPacket)

    #expect(packet.payload == [0x01, 0x02, 0x03, 0x04, 0x05])
    #expect(packet.padding == Array(repeating: 0x55, count: 6))
}

@Test
func binaryPacketParserRejectsPacketsBelowMinimumLength() throws {
    var parser = SSHBinaryPacketParser()
    parser.append(bytes: [0x00, 0x00, 0x00, 0x04])

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid packet length error")
    } catch {
        #expect(error as? SSHWireError == .invalidPacketLength(4))
    }
}

@Test
func binaryPacketParserAcceptsShortAADPacket() throws {
    let bytes = try SSHBinaryPacketSerializer(
        blockSize: 8,
        paddingByte: 0x55,
        alignmentExcludedByteCount: 4
    ).serialize(payload: [0x34])

    #expect(bytes.count == 12)
    #expect(Array(bytes.prefix(4)) == [0x00, 0x00, 0x00, 0x08])

    var parser = SSHBinaryPacketParser(
        blockSize: 8,
        alignmentExcludedByteCount: 4
    )
    parser.append(bytes: bytes)

    let parsedPacket = try parser.nextPacket()
    let packet = try #require(parsedPacket)
    #expect(packet.payload == [0x34])
    #expect(packet.padding == Array(repeating: 0x55, count: 6))
}

@Test
func binaryPacketParserRejectsPacketsWithTooLittlePadding() throws {
    var parser = SSHBinaryPacketParser()
    parser.append(bytes: [
        0x00, 0x00, 0x00, 0x0c,
        0x03,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b,
    ])

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid packet padding error")
    } catch {
        #expect(error as? SSHWireError == .invalidPacketPadding(3))
    }
}

@Test
func binaryPacketParserRejectsOverlargePackets() throws {
    var parser = SSHBinaryPacketParser()
    parser.append(bytes: [0x00, 0x00, 0x88, 0xb5])

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected packet-too-large error")
    } catch {
        #expect(error as? SSHWireError == .packetTooLarge(34_997))
    }
}
