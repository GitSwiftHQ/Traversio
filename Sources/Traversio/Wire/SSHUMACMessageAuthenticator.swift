// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import TraversioCCrypto

final class SSHUMACMessageAuthenticator {
    let length: Int

    private let context: OpaquePointer

    init(tagLength: Int, key: [UInt8]) throws {
        self.length = tagLength

        let context = key.withUnsafeBytes { keyBuffer in
            traversio_umac_new(
                tagLength,
                keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count
            )
        }
        guard let context else {
            throw SSHEncryptedBinaryPacketError.macOperationFailed
        }

        self.context = context
    }

    deinit {
        traversio_umac_free(self.context)
    }

    func authenticationCode(
        sequenceNumber: UInt32,
        packetBytes: [UInt8]
    ) throws -> [UInt8] {
        var tag = Array(repeating: UInt8.zero, count: self.length)
        let status = packetBytes.withUnsafeBytes { packetBuffer in
            tag.withUnsafeMutableBytes { tagBuffer in
                traversio_umac_authenticate(
                    self.context,
                    sequenceNumber,
                    packetBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    packetBytes.count,
                    tagBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        guard status == TRAVERSIO_UMAC_SUCCESS else {
            throw SSHEncryptedBinaryPacketError.macOperationFailed
        }

        return tag
    }
}
