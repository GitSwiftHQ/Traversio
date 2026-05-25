// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import TraversioCCrypto

final class SSHChaChaPoly1305Cryptor {
    private let context: OpaquePointer

    init(key: [UInt8]) throws {
        guard key.count == 64 else {
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }

        let context = key.withUnsafeBytes { keyBuffer in
            traversio_chachapoly_new(
                keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count
            )
        }
        guard let context else {
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }

        self.context = context
    }

    deinit {
        traversio_chachapoly_free(self.context)
    }

    func encrypt(packet: [UInt8], sequenceNumber: UInt32) throws -> (packet: [UInt8], tag: [UInt8]) {
        var encryptedPacket = Array(repeating: UInt8.zero, count: packet.count)
        var tag = Array(repeating: UInt8.zero, count: 16)
        let status = packet.withUnsafeBytes { packetBuffer in
            encryptedPacket.withUnsafeMutableBytes { encryptedPacketBuffer in
                tag.withUnsafeMutableBytes { tagBuffer in
                    traversio_chachapoly_encrypt_packet(
                        self.context,
                        sequenceNumber,
                        packetBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        packet.count,
                        encryptedPacketBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        tagBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard status == TRAVERSIO_CHACHAPOLY_SUCCESS else {
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }

        return (encryptedPacket, tag)
    }

    func decryptPacketLength(
        from encryptedPrefix: [UInt8],
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        precondition(encryptedPrefix.count >= 4)

        var packetLength: UInt32 = 0
        let status = encryptedPrefix.withUnsafeBytes { prefixBuffer in
            withUnsafeMutablePointer(to: &packetLength) { packetLengthPointer in
                traversio_chachapoly_get_length(
                    self.context,
                    sequenceNumber,
                    prefixBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    encryptedPrefix.count,
                    packetLengthPointer
                )
            }
        }

        guard status == TRAVERSIO_CHACHAPOLY_SUCCESS else {
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }

        var writer = SSHWireWriter(capacity: 4)
        writer.write(uint32: packetLength)
        return writer.bytes
    }

    func decrypt(
        packet encryptedPacket: [UInt8],
        tag: [UInt8],
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        var packet = Array(repeating: UInt8.zero, count: encryptedPacket.count)
        let status = encryptedPacket.withUnsafeBytes { packetBuffer in
            tag.withUnsafeBytes { tagBuffer in
                packet.withUnsafeMutableBytes { packetOutputBuffer in
                    traversio_chachapoly_decrypt_packet(
                        self.context,
                        sequenceNumber,
                        packetBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        encryptedPacket.count,
                        tagBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        packetOutputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        switch status {
        case TRAVERSIO_CHACHAPOLY_SUCCESS:
            return packet
        case TRAVERSIO_CHACHAPOLY_ERROR_INVALID_MAC:
            throw SSHEncryptedBinaryPacketError.invalidMAC
        default:
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }
    }
}
