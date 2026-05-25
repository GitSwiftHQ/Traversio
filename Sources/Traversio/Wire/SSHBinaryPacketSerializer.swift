// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHBinaryPacketSerializer: Sendable {
    let blockSize: Int
    let minimumPaddingLength: Int
    let paddingByte: UInt8
    let alignmentExcludedByteCount: Int

    init(
        blockSize: Int = 8,
        minimumPaddingLength: Int = 4,
        paddingByte: UInt8 = 0,
        alignmentExcludedByteCount: Int = 0
    ) {
        self.blockSize = max(blockSize, 8)
        self.minimumPaddingLength = max(minimumPaddingLength, 4)
        self.paddingByte = paddingByte
        self.alignmentExcludedByteCount = max(alignmentExcludedByteCount, 0)
    }

    func serialize(payload: [UInt8]) throws -> [UInt8] {
        let paddingLength = try self.paddingLength(forPayloadLength: payload.count)
        let packet = SSHBinaryPacket(
            payload: payload,
            padding: Array(repeating: self.paddingByte, count: paddingLength)
        )

        var writer = SSHWireWriter(capacity: 4 + Int(packet.packetLength))
        writer.write(uint32: packet.packetLength)
        writer.write(byte: UInt8(packet.padding.count))
        writer.write(rawBytes: payload)
        writer.write(rawBytes: packet.padding)
        return writer.bytes
    }

    private func paddingLength(forPayloadLength payloadLength: Int) throws -> Int {
        let minimumPacketSize =
            Self.minimumAlignedPacketLength(
                blockSize: self.blockSize,
                alignmentExcludedByteCount: self.alignmentExcludedByteCount
            ) + self.alignmentExcludedByteCount
        let alignedLength = payloadLength + 5 - self.alignmentExcludedByteCount
        var paddingLength = self.blockSize - (alignedLength % self.blockSize)

        if paddingLength < self.minimumPaddingLength {
            paddingLength += self.blockSize
        }

        while payloadLength + paddingLength + 5 < minimumPacketSize {
            paddingLength += self.blockSize
        }

        guard paddingLength <= Int(UInt8.max) else {
            throw SSHWireError.invalidPacketPadding(UInt8.max)
        }

        return paddingLength
    }

    private static func minimumAlignedPacketLength(
        blockSize: Int,
        alignmentExcludedByteCount: Int
    ) -> Int {
        alignmentExcludedByteCount == 0 ? max(16, blockSize) : blockSize
    }
}
