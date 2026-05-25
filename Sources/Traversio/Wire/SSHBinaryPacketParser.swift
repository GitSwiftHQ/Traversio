// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHBinaryPacketParser: Sendable {
    private let blockSize: Int
    private let maximumPacketSize: Int
    private let alignmentExcludedByteCount: Int
    private var bufferedBytes: [UInt8]

    init(
        blockSize: Int = 8,
        maximumPacketSize: Int = 35_000,
        alignmentExcludedByteCount: Int = 0
    ) {
        self.blockSize = max(blockSize, 8)
        self.maximumPacketSize = maximumPacketSize
        self.alignmentExcludedByteCount = max(alignmentExcludedByteCount, 0)
        self.bufferedBytes = []
    }

    mutating func append(bytes: [UInt8]) {
        self.bufferedBytes.append(contentsOf: bytes)
    }

    mutating func takeBufferedBytes() -> [UInt8] {
        defer { self.bufferedBytes.removeAll(keepingCapacity: false) }
        return self.bufferedBytes
    }

    mutating func nextPacket() throws -> SSHBinaryPacket? {
        guard self.bufferedBytes.count >= 4 else {
            return nil
        }

        var reader = SSHWireReader(bytes: Array(self.bufferedBytes.prefix(4)))
        let packetLength = try reader.readUInt32()

        guard packetLength >= 5 else {
            throw SSHWireError.invalidPacketLength(packetLength)
        }

        guard packetLength <= UInt32(self.maximumPacketSize - 4) else {
            throw SSHWireError.packetTooLarge(packetLength)
        }

        let totalPacketLength = 4 + Int(packetLength)

        let alignedPacketLength = totalPacketLength - self.alignmentExcludedByteCount
        guard
            alignedPacketLength >= Self.minimumAlignedPacketLength(
                blockSize: self.blockSize,
                alignmentExcludedByteCount: self.alignmentExcludedByteCount
            ),
            alignedPacketLength % self.blockSize == 0
        else {
            throw SSHWireError.invalidPacketLength(packetLength)
        }

        guard self.bufferedBytes.count >= totalPacketLength else {
            return nil
        }

        let packetBytes = Array(self.bufferedBytes[..<totalPacketLength])
        self.bufferedBytes.removeFirst(totalPacketLength)

        var packetReader = SSHWireReader(bytes: packetBytes)
        _ = try packetReader.readUInt32()
        let paddingLength = try packetReader.readByte()

        guard paddingLength >= 4 else {
            throw SSHWireError.invalidPacketPadding(paddingLength)
        }

        let payloadLength = Int(packetLength) - Int(paddingLength) - 1
        guard payloadLength >= 0 else {
            throw SSHWireError.invalidPacketPadding(paddingLength)
        }

        let payload = try packetReader.readRawBytes(count: payloadLength)
        let padding = try packetReader.readRawBytes(count: Int(paddingLength))

        guard packetReader.isAtEnd else {
            throw SSHWireError.invalidPacketLength(packetLength)
        }

        return SSHBinaryPacket(payload: payload, padding: padding)
    }

    static func consumeSinglePacket(
        from bytes: [UInt8],
        blockSize: Int = 8,
        maximumPacketSize: Int = 35_000,
        alignmentExcludedByteCount: Int = 0
    ) throws -> SSHBinaryPacket {
        var parser = SSHBinaryPacketParser(
            blockSize: blockSize,
            maximumPacketSize: maximumPacketSize,
            alignmentExcludedByteCount: alignmentExcludedByteCount
        )
        parser.append(bytes: bytes)

        guard let packet = try parser.nextPacket(), parser.bufferedBytes.isEmpty else {
            throw SSHWireError.invalidPacketLength(UInt32(bytes.count))
        }

        return packet
    }

    private static func minimumAlignedPacketLength(
        blockSize: Int,
        alignmentExcludedByteCount: Int
    ) -> Int {
        alignmentExcludedByteCount == 0 ? max(16, blockSize) : blockSize
    }
}
