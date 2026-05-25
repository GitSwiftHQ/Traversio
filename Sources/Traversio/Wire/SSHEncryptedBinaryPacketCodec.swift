// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CommonCrypto
import CryptoKit
import Foundation

enum SSHEncryptedBinaryPacketError: Error, Equatable, Sendable {
    case unsupportedEncryptionAlgorithm(String)
    case unsupportedMACAlgorithm(String)
    case unsupportedCompressionAlgorithm(String)
    case cryptorCreationFailed(Int32)
    case cryptorUpdateFailed(Int32)
    case invalidInitializationVectorLength(Int)
    case aeadOperationFailed
    case macOperationFailed
    case invalidMAC
    case compressionFailed
    case decompressionFailed
}

enum SSHTransportProtectionDirection: Sendable {
    case clientToServer
    case serverToClient
}

private enum SSHPacketProtection {
    case cipherAndMAC(cipher: SSHAESCTRCryptor, mac: SSHMessageAuthenticator)
    case aesGCM(cipher: SSHAESGCMCryptor)
    case chaChaPoly1305(cipher: SSHChaChaPoly1305Cryptor)

    var packetAlignmentExcludedByteCount: Int {
        switch self {
        case .cipherAndMAC(_, let mac):
            return mac.unencryptedPacketPrefixLength
        case .aesGCM, .chaChaPoly1305:
            return 4
        }
    }

    var unencryptedPacketPrefixLength: Int {
        switch self {
        case .cipherAndMAC(_, let mac):
            return mac.unencryptedPacketPrefixLength
        case .aesGCM:
            return 4
        case .chaChaPoly1305:
            return 0
        }
    }

    var trailerLength: Int {
        switch self {
        case .cipherAndMAC(_, let mac):
            return mac.length
        case .aesGCM:
            return 16
        case .chaChaPoly1305:
            return 16
        }
    }
}

struct SSHOutboundEncryptedPacketSerializer {
    private let packetSerializer: SSHBinaryPacketSerializer
    private let protection: SSHPacketProtection
    private var compression: SSHTransportPayloadCompressor
    private var sequenceNumber: UInt32

    init(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection,
        authenticationHasCompleted: Bool = false,
        initialSequenceNumber: UInt32 = 0,
        paddingByte: UInt8 = 0
    ) throws {
        self.protection = try Self.makeProtection(
            negotiatedAlgorithms: negotiatedAlgorithms,
            keyMaterial: keyMaterial,
            direction: direction
        )
        self.packetSerializer = SSHBinaryPacketSerializer(
            blockSize: try Self.blockSize(for: negotiatedAlgorithms, direction: direction),
            paddingByte: paddingByte,
            alignmentExcludedByteCount: self.protection.packetAlignmentExcludedByteCount
        )
        self.compression = try SSHTransportPayloadCompressor(
            algorithmName: Self.compressionAlgorithm(
                negotiatedAlgorithms: negotiatedAlgorithms,
                direction: direction
            ),
            authenticationHasCompleted: authenticationHasCompleted
        )
        self.sequenceNumber = initialSequenceNumber
    }

    mutating func serialize(payload: [UInt8]) throws -> [UInt8] {
        let clearPacket = try self.packetSerializer.serialize(
            payload: try self.compressedPayload(from: payload)
        )
        let protectedPacket: [UInt8]
        let trailer: [UInt8]

        switch self.protection {
        case let .cipherAndMAC(cipher, mac):
            let macInput: [UInt8]
            if mac.encryptThenMac {
                let clearPrefix = Array(clearPacket.prefix(mac.unencryptedPacketPrefixLength))
                let encryptedPayload = try cipher.update(
                    Array(clearPacket.dropFirst(mac.unencryptedPacketPrefixLength))
                )
                protectedPacket = clearPrefix + encryptedPayload
                macInput = protectedPacket
            } else {
                protectedPacket = try cipher.update(clearPacket)
                macInput = clearPacket
            }
            trailer = try mac.authenticationCode(
                sequenceNumber: self.sequenceNumber,
                packetBytes: macInput
            )
        case let .aesGCM(cipher):
            let clearPrefix = Array(
                clearPacket.prefix(self.protection.unencryptedPacketPrefixLength)
            )
            let encryptedPayload = try cipher.encrypt(
                Array(clearPacket.dropFirst(self.protection.unencryptedPacketPrefixLength)),
                authenticating: clearPrefix
            )
            protectedPacket = clearPrefix + encryptedPayload
            trailer = []
        case let .chaChaPoly1305(cipher):
            let result = try cipher.encrypt(
                packet: clearPacket,
                sequenceNumber: self.sequenceNumber
            )
            protectedPacket = result.packet
            trailer = result.tag
        }
        self.sequenceNumber &+= 1
        return protectedPacket + trailer
    }

    mutating func activateDelayedCompressionIfNeeded() {
        self.compression.activateIfNeeded()
    }

    var isCompressionActive: Bool {
        self.compression.isActive
    }

    fileprivate static func blockSize(
        for negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        direction: SSHTransportProtectionDirection
    ) throws -> Int {
        switch encryptionAlgorithm(negotiatedAlgorithms: negotiatedAlgorithms, direction: direction) {
        case "aes128-ctr", "aes256-ctr",
            "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
            return kCCBlockSizeAES128
        case "chacha20-poly1305@openssh.com":
            return 8
        case let algorithm:
            throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(algorithm)
        }
    }

    fileprivate static func encryptionKey(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection
    ) throws -> [UInt8] {
        switch encryptionAlgorithm(negotiatedAlgorithms: negotiatedAlgorithms, direction: direction) {
        case "aes128-ctr", "aes128-gcm@openssh.com":
            let key = direction == .clientToServer
                ? keyMaterial.encryptionKeyClientToServer
                : keyMaterial.encryptionKeyServerToClient
            guard key.count == kCCKeySizeAES128 else {
                throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(
                    encryptionAlgorithm(negotiatedAlgorithms: negotiatedAlgorithms, direction: direction)
                )
            }
            return key
        case "aes256-ctr", "aes256-gcm@openssh.com":
            let key = direction == .clientToServer
                ? keyMaterial.encryptionKeyClientToServer
                : keyMaterial.encryptionKeyServerToClient
            guard key.count == kCCKeySizeAES256 else {
                throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(
                    encryptionAlgorithm(negotiatedAlgorithms: negotiatedAlgorithms, direction: direction)
                )
            }
            return key
        case "chacha20-poly1305@openssh.com":
            let key = direction == .clientToServer
                ? keyMaterial.encryptionKeyClientToServer
                : keyMaterial.encryptionKeyServerToClient
            guard key.count == 64 else {
                throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(
                    encryptionAlgorithm(negotiatedAlgorithms: negotiatedAlgorithms, direction: direction)
                )
            }
            return key
        case let algorithm:
            throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(algorithm)
        }
    }

    fileprivate static func initialIV(
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection
    ) -> [UInt8] {
        direction == .clientToServer
            ? keyMaterial.initialIVClientToServer
            : keyMaterial.initialIVServerToClient
    }

    fileprivate static func macKey(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection
    ) throws -> SSHMessageAuthenticator {
        let algorithm = direction == .clientToServer
            ? negotiatedAlgorithms.macAlgorithmClientToServer
        : negotiatedAlgorithms.macAlgorithmServerToClient
        let key = direction == .clientToServer
            ? keyMaterial.integrityKeyClientToServer
            : keyMaterial.integrityKeyServerToClient

        return try SSHMessageAuthenticator(
            algorithm: algorithm,
            key: key
        )
    }

    private static func makeProtection(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection
    ) throws -> SSHPacketProtection {
        let algorithm = encryptionAlgorithm(
            negotiatedAlgorithms: negotiatedAlgorithms,
            direction: direction
        )
        let key = try encryptionKey(
            negotiatedAlgorithms: negotiatedAlgorithms,
            keyMaterial: keyMaterial,
            direction: direction
        )
        let iv = initialIV(
            keyMaterial: keyMaterial,
            direction: direction
        )

        switch algorithm {
        case "aes128-ctr", "aes256-ctr":
            return .cipherAndMAC(
                cipher: try SSHAESCTRCryptor(
                    operation: CCOperation(kCCEncrypt),
                    key: key,
                    iv: iv
                ),
                mac: try macKey(
                    negotiatedAlgorithms: negotiatedAlgorithms,
                    keyMaterial: keyMaterial,
                    direction: direction
                )
            )
        case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
            return .aesGCM(cipher: try SSHAESGCMCryptor(key: key, iv: iv))
        case "chacha20-poly1305@openssh.com":
            return .chaChaPoly1305(cipher: try SSHChaChaPoly1305Cryptor(key: key))
        default:
            throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(algorithm)
        }
    }

    fileprivate static func encryptionAlgorithm(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        direction: SSHTransportProtectionDirection
    ) -> String {
        direction == .clientToServer
            ? negotiatedAlgorithms.encryptionAlgorithmClientToServer
            : negotiatedAlgorithms.encryptionAlgorithmServerToClient
    }

    fileprivate static func compressionAlgorithm(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        direction: SSHTransportProtectionDirection
    ) -> String {
        direction == .clientToServer
            ? negotiatedAlgorithms.compressionAlgorithmClientToServer
            : negotiatedAlgorithms.compressionAlgorithmServerToClient
    }

    private mutating func compressedPayload(from payload: [UInt8]) throws -> [UInt8] {
        do {
            return try self.compression.compress(payload)
        } catch let error as SSHTransportCompressionError {
            switch error {
            case let .unsupportedCompressionAlgorithm(algorithm):
                throw SSHEncryptedBinaryPacketError.unsupportedCompressionAlgorithm(algorithm)
            case .compressionFailed:
                throw SSHEncryptedBinaryPacketError.compressionFailed
            case .decompressionFailed:
                throw SSHEncryptedBinaryPacketError.decompressionFailed
            }
        }
    }
}

struct SSHInboundEncryptedPacketParser {
    private let blockSize: Int
    private let maximumPacketSize: Int
    private let protection: SSHPacketProtection
    private var decompression: SSHTransportPayloadDecompressor

    private var sequenceNumber: UInt32
    private var encryptedBuffer: [UInt8]
    private var currentPacketBytes: [UInt8]
    private var expectedPacketLength: Int?

    init(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection,
        authenticationHasCompleted: Bool = false,
        initialSequenceNumber: UInt32 = 0,
        maximumPacketSize: Int = 35_000
    ) throws {
        self.blockSize = try SSHOutboundEncryptedPacketSerializer.blockSize(
            for: negotiatedAlgorithms,
            direction: direction
        )
        self.maximumPacketSize = maximumPacketSize
        self.protection = try Self.makeProtection(
            negotiatedAlgorithms: negotiatedAlgorithms,
            keyMaterial: keyMaterial,
            direction: direction
        )
        self.decompression = try SSHTransportPayloadDecompressor(
            algorithmName: SSHOutboundEncryptedPacketSerializer.compressionAlgorithm(
                negotiatedAlgorithms: negotiatedAlgorithms,
                direction: direction
            ),
            authenticationHasCompleted: authenticationHasCompleted
        )
        self.sequenceNumber = initialSequenceNumber
        self.encryptedBuffer = []
        self.currentPacketBytes = []
        self.expectedPacketLength = nil
    }

    mutating func append(bytes: [UInt8]) {
        self.encryptedBuffer.append(contentsOf: bytes)
    }

    mutating func takeBufferedBytes() -> [UInt8] {
        precondition(
            self.currentPacketBytes.isEmpty && self.expectedPacketLength == nil,
            "Buffered bytes may only be transferred between packets."
        )

        defer {
            self.encryptedBuffer.removeAll(keepingCapacity: false)
        }
        return self.encryptedBuffer
    }

    mutating func nextPacket() throws -> SSHBinaryPacket? {
        switch self.protection {
        case .aesGCM:
            return try self.nextAEADPacket()
        case .chaChaPoly1305:
            return try self.nextChaChaPoly1305Packet()
        case .cipherAndMAC(_, let mac) where mac.encryptThenMac:
            return try self.nextEncryptThenMACPacket()
        case .cipherAndMAC(let cipher, let mac):
            try self.decryptAvailableBytes(using: cipher, targetCount: 4)

            if self.expectedPacketLength == nil, self.currentPacketBytes.count >= 4 {
                self.expectedPacketLength = try Self.packetByteLength(
                    from: self.currentPacketBytes,
                    blockSize: self.blockSize,
                    maximumPacketSize: self.maximumPacketSize
                )
            }

            guard let expectedPacketLength else {
                return nil
            }

            try self.decryptAvailableBytes(using: cipher, targetCount: expectedPacketLength)
            guard self.currentPacketBytes.count >= expectedPacketLength else {
                return nil
            }

            guard self.encryptedBuffer.count >= mac.length else {
                return nil
            }

            let receivedMAC = Array(self.encryptedBuffer.prefix(mac.length))
            let expectedMAC = try mac.authenticationCode(
                sequenceNumber: self.sequenceNumber,
                packetBytes: self.currentPacketBytes
            )
            guard Self.constantTimeEquals(receivedMAC, expectedMAC) else {
                throw SSHEncryptedBinaryPacketError.invalidMAC
            }

            self.encryptedBuffer.removeFirst(mac.length)
            let packetBytes = self.currentPacketBytes
            self.currentPacketBytes.removeAll(keepingCapacity: true)
            self.expectedPacketLength = nil
            self.sequenceNumber &+= 1

            return try self.decompressedPacket(
                from: packetBytes,
                blockSize: self.blockSize,
                maximumPacketSize: self.maximumPacketSize
            )
        }
    }

    mutating func activateDelayedCompressionIfNeeded() {
        self.decompression.activateIfNeeded()
    }

    var isCompressionActive: Bool {
        self.decompression.isActive
    }

    private mutating func nextEncryptThenMACPacket() throws -> SSHBinaryPacket? {
        guard case let .cipherAndMAC(cipher, mac) = self.protection else {
            return nil
        }

        if self.expectedPacketLength == nil {
            guard self.encryptedBuffer.count >= mac.unencryptedPacketPrefixLength else {
                return nil
            }

            self.expectedPacketLength = try Self.packetByteLength(
                from: Array(self.encryptedBuffer.prefix(mac.unencryptedPacketPrefixLength)),
                blockSize: self.blockSize,
                maximumPacketSize: self.maximumPacketSize,
                alignmentExcludedByteCount: mac.unencryptedPacketPrefixLength
            )
        }

        guard let expectedPacketLength else {
            return nil
        }

        guard self.encryptedBuffer.count >= expectedPacketLength + mac.length else {
            return nil
        }

        let protectedPacket = Array(self.encryptedBuffer.prefix(expectedPacketLength))
        let receivedMAC = Array(
            self.encryptedBuffer
                .dropFirst(expectedPacketLength)
                .prefix(mac.length)
        )
        let expectedMAC = try mac.authenticationCode(
            sequenceNumber: self.sequenceNumber,
            packetBytes: protectedPacket
        )
        guard Self.constantTimeEquals(receivedMAC, expectedMAC) else {
            throw SSHEncryptedBinaryPacketError.invalidMAC
        }

        let clearPrefix = Array(protectedPacket.prefix(mac.unencryptedPacketPrefixLength))
        let decryptedPayload = try cipher.update(
            Array(protectedPacket.dropFirst(mac.unencryptedPacketPrefixLength))
        )
        let clearPacket = clearPrefix + decryptedPayload

        self.encryptedBuffer.removeFirst(expectedPacketLength + mac.length)
        self.expectedPacketLength = nil
        self.sequenceNumber &+= 1

        return try self.decompressedPacket(
            from: clearPacket,
            blockSize: self.blockSize,
            maximumPacketSize: self.maximumPacketSize,
            alignmentExcludedByteCount: mac.unencryptedPacketPrefixLength
        )
    }

    private mutating func nextAEADPacket() throws -> SSHBinaryPacket? {
        guard case let .aesGCM(cipher) = self.protection else {
            return nil
        }

        if self.expectedPacketLength == nil {
            guard self.encryptedBuffer.count >= self.protection.unencryptedPacketPrefixLength else {
                return nil
            }

            self.expectedPacketLength = try Self.packetByteLength(
                from: Array(self.encryptedBuffer.prefix(self.protection.unencryptedPacketPrefixLength)),
                blockSize: self.blockSize,
                maximumPacketSize: self.maximumPacketSize,
                alignmentExcludedByteCount: self.protection.unencryptedPacketPrefixLength
            )
        }

        guard let expectedPacketLength else {
            return nil
        }

        guard self.encryptedBuffer.count >= expectedPacketLength + self.protection.trailerLength else {
            return nil
        }

        let protectedPacket = Array(self.encryptedBuffer.prefix(expectedPacketLength))
        let clearPrefix = Array(
            protectedPacket.prefix(self.protection.unencryptedPacketPrefixLength)
        )
        let receivedTag = Array(
            self.encryptedBuffer
                .dropFirst(expectedPacketLength)
                .prefix(self.protection.trailerLength)
        )
        let ciphertext = Array(
            protectedPacket.dropFirst(self.protection.unencryptedPacketPrefixLength)
        )
        let decryptedPayload = try cipher.decrypt(
            ciphertext,
            tag: receivedTag,
            authenticating: clearPrefix
        )
        let clearPacket = clearPrefix + decryptedPayload

        self.encryptedBuffer.removeFirst(expectedPacketLength + self.protection.trailerLength)
        self.expectedPacketLength = nil
        self.sequenceNumber &+= 1

        return try self.decompressedPacket(
            from: clearPacket,
            blockSize: self.blockSize,
            maximumPacketSize: self.maximumPacketSize,
            alignmentExcludedByteCount: self.protection.unencryptedPacketPrefixLength
        )
    }

    private mutating func nextChaChaPoly1305Packet() throws -> SSHBinaryPacket? {
        guard case let .chaChaPoly1305(cipher) = self.protection else {
            return nil
        }

        if self.expectedPacketLength == nil {
            guard self.encryptedBuffer.count >= 4 else {
                return nil
            }

            self.expectedPacketLength = try Self.packetByteLength(
                from: try cipher.decryptPacketLength(
                    from: Array(self.encryptedBuffer.prefix(4)),
                    sequenceNumber: self.sequenceNumber
                ),
                blockSize: self.blockSize,
                maximumPacketSize: self.maximumPacketSize,
                alignmentExcludedByteCount: self.protection.packetAlignmentExcludedByteCount
            )
        }

        guard let expectedPacketLength else {
            return nil
        }

        guard self.encryptedBuffer.count >= expectedPacketLength + self.protection.trailerLength else {
            return nil
        }

        let encryptedPacket = Array(self.encryptedBuffer.prefix(expectedPacketLength))
        let receivedTag = Array(
            self.encryptedBuffer
                .dropFirst(expectedPacketLength)
                .prefix(self.protection.trailerLength)
        )
        let clearPacket = try cipher.decrypt(
            packet: encryptedPacket,
            tag: receivedTag,
            sequenceNumber: self.sequenceNumber
        )

        self.encryptedBuffer.removeFirst(expectedPacketLength + self.protection.trailerLength)
        self.expectedPacketLength = nil
        self.sequenceNumber &+= 1

        return try self.decompressedPacket(
            from: clearPacket,
            blockSize: self.blockSize,
            maximumPacketSize: self.maximumPacketSize,
            alignmentExcludedByteCount: self.protection.packetAlignmentExcludedByteCount
        )
    }

    private mutating func decryptAvailableBytes(
        using cipher: SSHAESCTRCryptor,
        targetCount: Int
    ) throws {
        let needed = targetCount - self.currentPacketBytes.count
        guard needed > 0, !self.encryptedBuffer.isEmpty else {
            return
        }

        let encryptedPrefix = Array(self.encryptedBuffer.prefix(needed))
        let decryptedBytes = try cipher.update(encryptedPrefix)
        self.currentPacketBytes.append(contentsOf: decryptedBytes)
        self.encryptedBuffer.removeFirst(encryptedPrefix.count)
    }

    private static func packetByteLength(
        from packetPrefix: [UInt8],
        blockSize: Int,
        maximumPacketSize: Int,
        alignmentExcludedByteCount: Int = 0
    ) throws -> Int {
        var reader = SSHWireReader(bytes: Array(packetPrefix.prefix(4)))
        let packetLength = try reader.readUInt32()

        guard packetLength >= 5 else {
            throw SSHWireError.invalidPacketLength(packetLength)
        }

        guard packetLength <= UInt32(maximumPacketSize - 4) else {
            throw SSHWireError.packetTooLarge(packetLength)
        }

        let totalPacketLength = 4 + Int(packetLength)
        let alignedPacketLength = totalPacketLength - alignmentExcludedByteCount
        guard
            alignedPacketLength >= minimumAlignedPacketLength(
                blockSize: blockSize,
                alignmentExcludedByteCount: alignmentExcludedByteCount
            ),
            alignedPacketLength % blockSize == 0
        else {
            throw SSHWireError.invalidPacketLength(packetLength)
        }

        return totalPacketLength
    }

    private static func minimumAlignedPacketLength(
        blockSize: Int,
        alignmentExcludedByteCount: Int
    ) -> Int {
        alignmentExcludedByteCount == 0 ? max(16, blockSize) : blockSize
    }

    private static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }

        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }

        return difference == 0
    }

    private static func makeProtection(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyMaterial: SSHTransportKeyMaterial,
        direction: SSHTransportProtectionDirection
    ) throws -> SSHPacketProtection {
        let algorithm = SSHOutboundEncryptedPacketSerializer.encryptionAlgorithm(
            negotiatedAlgorithms: negotiatedAlgorithms,
            direction: direction
        )
        let key = try SSHOutboundEncryptedPacketSerializer.encryptionKey(
            negotiatedAlgorithms: negotiatedAlgorithms,
            keyMaterial: keyMaterial,
            direction: direction
        )
        let iv = SSHOutboundEncryptedPacketSerializer.initialIV(
            keyMaterial: keyMaterial,
            direction: direction
        )

        switch algorithm {
        case "aes128-ctr", "aes256-ctr":
            return .cipherAndMAC(
                cipher: try SSHAESCTRCryptor(
                    operation: CCOperation(kCCDecrypt),
                    key: key,
                    iv: iv
                ),
                mac: try SSHOutboundEncryptedPacketSerializer.macKey(
                    negotiatedAlgorithms: negotiatedAlgorithms,
                    keyMaterial: keyMaterial,
                    direction: direction
                )
            )
        case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
            return .aesGCM(cipher: try SSHAESGCMCryptor(key: key, iv: iv))
        case "chacha20-poly1305@openssh.com":
            return .chaChaPoly1305(cipher: try SSHChaChaPoly1305Cryptor(key: key))
        default:
            throw SSHEncryptedBinaryPacketError.unsupportedEncryptionAlgorithm(algorithm)
        }
    }

    private mutating func decompressedPacket(
        from bytes: [UInt8],
        blockSize: Int,
        maximumPacketSize: Int,
        alignmentExcludedByteCount: Int = 0
    ) throws -> SSHBinaryPacket {
        let packet = try SSHBinaryPacketParser.consumeSinglePacket(
            from: bytes,
            blockSize: blockSize,
            maximumPacketSize: maximumPacketSize,
            alignmentExcludedByteCount: alignmentExcludedByteCount
        )

        do {
            return SSHBinaryPacket(
                payload: try self.decompression.decompress(packet.payload),
                padding: packet.padding
            )
        } catch let error as SSHTransportCompressionError {
            switch error {
            case let .unsupportedCompressionAlgorithm(algorithm):
                throw SSHEncryptedBinaryPacketError.unsupportedCompressionAlgorithm(algorithm)
            case .compressionFailed:
                throw SSHEncryptedBinaryPacketError.compressionFailed
            case .decompressionFailed:
                throw SSHEncryptedBinaryPacketError.decompressionFailed
            }
        }
    }
}

private struct SSHMessageAuthenticator {
    let algorithm: SSHMessageAuthenticatorAlgorithm
    let key: [UInt8]
    let umacAuthenticator: SSHUMACMessageAuthenticator?
    let encryptThenMac: Bool

    init(algorithm: String, key: [UInt8]) throws {
        switch algorithm {
        case "hmac-sha2-256":
            self.algorithm = .sha256
            self.umacAuthenticator = nil
            self.encryptThenMac = false
        case "hmac-sha2-512":
            self.algorithm = .sha512
            self.umacAuthenticator = nil
            self.encryptThenMac = false
        case "hmac-sha2-256-etm@openssh.com":
            self.algorithm = .sha256
            self.umacAuthenticator = nil
            self.encryptThenMac = true
        case "hmac-sha2-512-etm@openssh.com":
            self.algorithm = .sha512
            self.umacAuthenticator = nil
            self.encryptThenMac = true
        case "umac-64@openssh.com":
            self.algorithm = .umac64
            self.umacAuthenticator = try SSHUMACMessageAuthenticator(tagLength: 8, key: key)
            self.encryptThenMac = false
        case "umac-128@openssh.com":
            self.algorithm = .umac128
            self.umacAuthenticator = try SSHUMACMessageAuthenticator(tagLength: 16, key: key)
            self.encryptThenMac = false
        case "umac-64-etm@openssh.com":
            self.algorithm = .umac64
            self.umacAuthenticator = try SSHUMACMessageAuthenticator(tagLength: 8, key: key)
            self.encryptThenMac = true
        case "umac-128-etm@openssh.com":
            self.algorithm = .umac128
            self.umacAuthenticator = try SSHUMACMessageAuthenticator(tagLength: 16, key: key)
            self.encryptThenMac = true
        default:
            throw SSHEncryptedBinaryPacketError.unsupportedMACAlgorithm(algorithm)
        }

        self.key = key
    }

    var length: Int {
        switch self.algorithm {
        case .sha256:
            return 32
        case .sha512:
            return 64
        case .umac64:
            return 8
        case .umac128:
            return 16
        }
    }

    var unencryptedPacketPrefixLength: Int {
        self.encryptThenMac ? 4 : 0
    }

    func authenticationCode(sequenceNumber: UInt32, packetBytes: [UInt8]) throws -> [UInt8] {
        if let umacAuthenticator {
            return try umacAuthenticator.authenticationCode(
                sequenceNumber: sequenceNumber,
                packetBytes: packetBytes
            )
        }

        var writer = SSHWireWriter(capacity: 4 + packetBytes.count)
        writer.write(uint32: sequenceNumber)
        writer.write(rawBytes: packetBytes)
        var digest = Array(repeating: UInt8.zero, count: self.length)

        self.key.withUnsafeBytes { keyBuffer in
            writer.bytes.withUnsafeBytes { dataBuffer in
                digest.withUnsafeMutableBytes { digestBuffer in
                    CCHmac(
                        self.algorithm.ccAlgorithm,
                        keyBuffer.baseAddress,
                        self.key.count,
                        dataBuffer.baseAddress,
                        writer.bytes.count,
                        digestBuffer.baseAddress
                    )
                }
            }
        }

        return digest
    }
}

private enum SSHMessageAuthenticatorAlgorithm {
    case sha256
    case sha512
    case umac64
    case umac128

    var ccAlgorithm: CCHmacAlgorithm {
        switch self {
        case .sha256:
            return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .sha512:
            return CCHmacAlgorithm(kCCHmacAlgSHA512)
        case .umac64, .umac128:
            preconditionFailure("UMAC does not use CommonCrypto HMAC")
        }
    }
}

private struct SSHAESGCMNonce {
    private var bytes: [UInt8]

    init(_ bytes: [UInt8]) throws {
        guard bytes.count == 12 else {
            throw SSHEncryptedBinaryPacketError.invalidInitializationVectorLength(bytes.count)
        }

        self.bytes = bytes
    }

    mutating func increment() {
        for index in stride(from: 11, through: 4, by: -1) {
            let (newValue, overflow) = self.bytes[index].addingReportingOverflow(1)
            self.bytes[index] = newValue
            if !overflow {
                break
            }
        }
    }

    var currentBytes: [UInt8] {
        self.bytes
    }
}

private final class SSHAESGCMCryptor {
    private let key: [UInt8]
    private var nonce: SSHAESGCMNonce

    init(key: [UInt8], iv: [UInt8]) throws {
        self.key = key
        self.nonce = try SSHAESGCMNonce(iv)
    }

    func encrypt(_ plaintext: [UInt8], authenticating additionalData: [UInt8]) throws -> [UInt8] {
        do {
            let symmetricKey = SymmetricKey(data: self.key)
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: symmetricKey,
                nonce: try AES.GCM.Nonce(data: self.nonce.currentBytes),
                authenticating: additionalData
            )
            self.nonce.increment()
            return Array(sealedBox.ciphertext) + Array(sealedBox.tag)
        } catch {
            throw SSHEncryptedBinaryPacketError.aeadOperationFailed
        }
    }

    func decrypt(
        _ ciphertext: [UInt8],
        tag: [UInt8],
        authenticating additionalData: [UInt8]
    ) throws -> [UInt8] {
        do {
            let symmetricKey = SymmetricKey(data: self.key)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: self.nonce.currentBytes),
                ciphertext: ciphertext,
                tag: tag
            )
            let plaintext = try AES.GCM.open(
                sealedBox,
                using: symmetricKey,
                authenticating: additionalData
            )
            self.nonce.increment()
            return Array(plaintext)
        } catch {
            throw SSHEncryptedBinaryPacketError.invalidMAC
        }
    }
}

private final class SSHAESCTRCryptor {
    private let cryptor: CCCryptorRef

    init(operation: CCOperation, key: [UInt8], iv: [UInt8]) throws {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    operation,
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress,
                    keyBuffer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }

        guard status == kCCSuccess, let cryptor else {
            throw SSHEncryptedBinaryPacketError.cryptorCreationFailed(status)
        }

        self.cryptor = cryptor
    }

    deinit {
        CCCryptorRelease(self.cryptor)
    }

    func update(_ bytes: [UInt8]) throws -> [UInt8] {
        guard !bytes.isEmpty else {
            return []
        }

        var output = Array(repeating: UInt8.zero, count: bytes.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputCount = 0
        let status = bytes.withUnsafeBytes { inputBuffer in
            output.withUnsafeMutableBytes { outputBuffer in
                CCCryptorUpdate(
                    self.cryptor,
                    inputBuffer.baseAddress,
                    bytes.count,
                    outputBuffer.baseAddress,
                    outputCapacity,
                    &outputCount
                )
            }
        }

        guard status == kCCSuccess else {
            throw SSHEncryptedBinaryPacketError.cryptorUpdateFailed(status)
        }

        output.removeSubrange(outputCount..<output.count)
        return output
    }
}
