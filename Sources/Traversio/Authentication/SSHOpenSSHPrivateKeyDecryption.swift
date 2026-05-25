// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CommonCrypto
import Foundation
import TraversioCCrypto

enum SSHOpenSSHPrivateKeyCipher: Equatable {
    case none
    case aes128CTR
    case aes192CTR
    case aes256CTR
    case aes128CBC
    case aes192CBC
    case aes256CBC

    init(name: String) throws {
        switch name {
        case "none":
            self = .none
        case "aes128-ctr":
            self = .aes128CTR
        case "aes192-ctr":
            self = .aes192CTR
        case "aes256-ctr":
            self = .aes256CTR
        case "aes128-cbc":
            self = .aes128CBC
        case "aes192-cbc":
            self = .aes192CBC
        case "aes256-cbc":
            self = .aes256CBC
        default:
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyCipher(name)
        }
    }

    var isEncrypted: Bool {
        self != .none
    }

    var name: String {
        switch self {
        case .none:
            return "none"
        case .aes128CTR:
            return "aes128-ctr"
        case .aes192CTR:
            return "aes192-ctr"
        case .aes256CTR:
            return "aes256-ctr"
        case .aes128CBC:
            return "aes128-cbc"
        case .aes192CBC:
            return "aes192-cbc"
        case .aes256CBC:
            return "aes256-cbc"
        }
    }

    var keyByteCount: Int {
        switch self {
        case .none:
            return 0
        case .aes128CTR, .aes128CBC:
            return kCCKeySizeAES128
        case .aes192CTR, .aes192CBC:
            return kCCKeySizeAES192
        case .aes256CTR, .aes256CBC:
            return kCCKeySizeAES256
        }
    }

    var ivByteCount: Int {
        switch self {
        case .none:
            return 0
        case .aes128CTR, .aes192CTR, .aes256CTR,
             .aes128CBC, .aes192CBC, .aes256CBC:
            return kCCBlockSizeAES128
        }
    }

    var blockSize: Int {
        switch self {
        case .none:
            return 8
        case .aes128CTR, .aes192CTR, .aes256CTR,
             .aes128CBC, .aes192CBC, .aes256CBC:
            return kCCBlockSizeAES128
        }
    }

    func decrypt(
        encryptedPrivateKeyBlock: [UInt8],
        using keyMaterial: [UInt8]
    ) throws -> [UInt8] {
        try self.crypt(
            privateKeyBlock: encryptedPrivateKeyBlock,
            using: keyMaterial,
            operation: CCOperation(kCCDecrypt)
        )
    }

    func encrypt(
        privateKeyBlock: [UInt8],
        using keyMaterial: [UInt8]
    ) throws -> [UInt8] {
        try self.crypt(
            privateKeyBlock: privateKeyBlock,
            using: keyMaterial,
            operation: CCOperation(kCCEncrypt)
        )
    }

    private func crypt(
        privateKeyBlock: [UInt8],
        using keyMaterial: [UInt8],
        operation: CCOperation
    ) throws -> [UInt8] {
        guard self.isEncrypted else {
            return privateKeyBlock
        }

        guard privateKeyBlock.count >= self.blockSize,
              privateKeyBlock.count.isMultiple(of: self.blockSize),
              keyMaterial.count == self.keyByteCount + self.ivByteCount else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        let key = Array(keyMaterial.prefix(self.keyByteCount))
        let iv = Array(keyMaterial.dropFirst(self.keyByteCount))

        let transformed = try self.makeCryptor(
            operation: operation,
            key: key,
            iv: iv
        ).update(privateKeyBlock)
        guard transformed.count == privateKeyBlock.count else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
        return transformed
    }

    private func makeCryptor(
        operation: CCOperation,
        key: [UInt8],
        iv: [UInt8]
    ) throws -> SSHOpenSSHPrivateKeyAESCryptor {
        switch self {
        case .none:
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        case .aes128CTR, .aes192CTR, .aes256CTR:
            return try SSHOpenSSHPrivateKeyAESCryptor(
                operation: operation,
                mode: CCMode(kCCModeCTR),
                modeOptions: CCModeOptions(kCCModeOptionCTR_BE),
                key: key,
                iv: iv
            )
        case .aes128CBC, .aes192CBC, .aes256CBC:
            return try SSHOpenSSHPrivateKeyAESCryptor(
                operation: operation,
                mode: CCMode(kCCModeCBC),
                modeOptions: CCModeOptions(0),
                key: key,
                iv: iv
            )
        }
    }
}

struct SSHOpenSSHPrivateKeyKDFOptions: Equatable {
    let salt: [UInt8]
    let rounds: UInt32
}

enum SSHOpenSSHPrivateKeyKDF: Equatable {
    case none
    case bcrypt(SSHOpenSSHPrivateKeyKDFOptions)

    init(name: String, options: [UInt8]) throws {
        switch name {
        case "none":
            guard options.isEmpty else {
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            }
            self = .none
        case "bcrypt":
            var reader = SSHWireReader(bytes: options)
            let salt = try reader.readString()
            let rounds = try reader.readUInt32()
            guard !salt.isEmpty, reader.isAtEnd else {
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            }
            self = .bcrypt(SSHOpenSSHPrivateKeyKDFOptions(salt: salt, rounds: rounds))
        default:
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyKDF(name)
        }
    }

    func deriveKeyMaterial(
        passphrase: String?,
        byteCount: Int
    ) throws -> [UInt8] {
        guard byteCount >= 0 else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        switch self {
        case .none:
            return []
        case let .bcrypt(options):
            guard let passphrase, !passphrase.isEmpty else {
                throw SSHAuthenticationMethodError.missingOpenSSHPrivateKeyPassphrase
            }

            let passphraseBytes = Array(passphrase.utf8)
            var derivedKey = Array(repeating: UInt8.zero, count: byteCount)
            let derivedKeyCount = derivedKey.count
            let status = passphraseBytes.withUnsafeBytes { passphraseBuffer in
                options.salt.withUnsafeBytes { saltBuffer in
                    derivedKey.withUnsafeMutableBytes { derivedKeyBuffer in
                        traversio_bcrypt_pbkdf(
                            passphraseBuffer.baseAddress?.assumingMemoryBound(to: CChar.self),
                            passphraseBytes.count,
                            saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            options.salt.count,
                            derivedKeyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            derivedKeyCount,
                            options.rounds
                        )
                    }
                }
            }

            guard status == TRAVERSIO_BCRYPT_PBKDF_SUCCESS else {
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            }
            return derivedKey
        }
    }

    var name: String {
        switch self {
        case .none:
            return "none"
        case .bcrypt:
            return "bcrypt"
        }
    }

    var encodedOptions: [UInt8] {
        switch self {
        case .none:
            return []
        case let .bcrypt(options):
            var writer = SSHWireWriter()
            writer.write(string: options.salt)
            writer.write(uint32: options.rounds)
            return writer.bytes
        }
    }
}

private final class SSHOpenSSHPrivateKeyAESCryptor {
    private let cryptor: CCCryptorRef

    init(
        operation: CCOperation,
        mode: CCMode,
        modeOptions: CCModeOptions,
        key: [UInt8],
        iv: [UInt8]
    ) throws {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    operation,
                    mode,
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress,
                    keyBuffer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    modeOptions,
                    &cryptor
                )
            }
        }

        guard status == kCCSuccess, let cryptor else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
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
        let updateStatus = bytes.withUnsafeBytes { inputBuffer in
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
        guard updateStatus == kCCSuccess else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        var finalCount = 0
        let finalCapacity = outputCapacity - outputCount
        let finalStatus = output.withUnsafeMutableBytes { outputBuffer in
            CCCryptorFinal(
                self.cryptor,
                outputBuffer.baseAddress?.advanced(by: outputCount),
                finalCapacity,
                &finalCount
            )
        }
        guard finalStatus == kCCSuccess else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        output.removeSubrange((outputCount + finalCount)..<output.count)
        return output
    }
}
