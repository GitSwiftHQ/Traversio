// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CommonCrypto
import CryptoKit
import Foundation

enum SSHLegacyPrivateKeyPEMDecryption {
    static func decrypt(
        encryptedDERBytes: [UInt8],
        headers: [String],
        passphrase: String?,
        pemType: String
    ) throws -> [UInt8] {
        guard let passphrase, passphrase.isEmpty == false else {
            throw SSHAuthenticationMethodError.missingLegacyPrivateKeyPEMPassphrase(pemType)
        }

        let dekInfo = try self.requireDEKInfo(headers)
        let cipher = try Cipher(name: dekInfo.cipherName)
        let iv = try self.decodeHex(dekInfo.initializationVectorHex)
        guard iv.count == cipher.initializationVectorByteCount else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        let salt = Array(iv.prefix(cipher.saltByteCount))
        let key = self.evpBytesToKey(
            passphrase: Array(passphrase.utf8),
            salt: salt,
            byteCount: cipher.keyByteCount
        )
        return try cipher.decrypt(
            encryptedDERBytes,
            key: key,
            initializationVector: iv,
            pemType: pemType
        )
    }

    private static func requireDEKInfo(
        _ headers: [String]
    ) throws -> (cipherName: String, initializationVectorHex: String) {
        guard let rawValue = self.headerValue(named: "DEK-Info", in: headers) else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        let parts = rawValue.split(separator: ",", maxSplits: 1).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard parts.count == 2,
              parts[0].isEmpty == false,
              parts[1].isEmpty == false else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        return (parts[0], parts[1])
    }

    private static func headerValue(
        named name: String,
        in headers: [String]
    ) -> String? {
        for header in headers {
            let parts = header.split(separator: ":", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            guard parts.count == 2 else {
                continue
            }
            if parts[0].caseInsensitiveCompare(name) == .orderedSame {
                return parts[1]
            }
        }
        return nil
    }

    private static func decodeHex(_ text: String) throws -> [UInt8] {
        guard text.count.isMultiple(of: 2) else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let nextIndex = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<nextIndex], radix: 16) else {
                throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
            }
            bytes.append(byte)
            index = nextIndex
        }
        return bytes
    }

    private static func evpBytesToKey(
        passphrase: [UInt8],
        salt: [UInt8],
        byteCount: Int
    ) -> [UInt8] {
        var derivedKey: [UInt8] = []
        var previousDigest: [UInt8] = []

        while derivedKey.count < byteCount {
            let digestInput = previousDigest + passphrase + salt
            previousDigest = Array(Insecure.MD5.hash(data: Data(digestInput)))
            derivedKey += previousDigest
        }

        return Array(derivedKey.prefix(byteCount))
    }

    private enum Cipher {
        case aes128CBC
        case aes192CBC
        case aes256CBC
        case desEDE3CBC

        init(name: String) throws {
            switch name {
            case "AES-128-CBC":
                self = .aes128CBC
            case "AES-192-CBC":
                self = .aes192CBC
            case "AES-256-CBC":
                self = .aes256CBC
            case "DES-EDE3-CBC":
                self = .desEDE3CBC
            default:
                throw SSHAuthenticationMethodError.unsupportedLegacyPrivateKeyPEMCipher(name)
            }
        }

        var algorithm: CCAlgorithm {
            switch self {
            case .aes128CBC, .aes192CBC, .aes256CBC:
                return CCAlgorithm(kCCAlgorithmAES)
            case .desEDE3CBC:
                return CCAlgorithm(kCCAlgorithm3DES)
            }
        }

        var keyByteCount: Int {
            switch self {
            case .aes128CBC:
                return kCCKeySizeAES128
            case .aes192CBC:
                return kCCKeySizeAES192
            case .aes256CBC:
                return kCCKeySizeAES256
            case .desEDE3CBC:
                return kCCKeySize3DES
            }
        }

        var initializationVectorByteCount: Int {
            switch self {
            case .aes128CBC, .aes192CBC, .aes256CBC:
                return kCCBlockSizeAES128
            case .desEDE3CBC:
                return kCCBlockSize3DES
            }
        }

        var saltByteCount: Int {
            min(8, self.initializationVectorByteCount)
        }

        func decrypt(
            _ bytes: [UInt8],
            key: [UInt8],
            initializationVector: [UInt8],
            pemType: String
        ) throws -> [UInt8] {
            guard bytes.isEmpty == false,
                  key.count == self.keyByteCount,
                  initializationVector.count == self.initializationVectorByteCount else {
                throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
            }

            var output = Array(repeating: UInt8.zero, count: bytes.count + self.initializationVectorByteCount)
            let outputCapacity = output.count
            var outputCount = 0
            let status = key.withUnsafeBytes { keyBuffer in
                initializationVector.withUnsafeBytes { ivBuffer in
                    bytes.withUnsafeBytes { inputBuffer in
                        output.withUnsafeMutableBytes { outputBuffer in
                            CCCrypt(
                                CCOperation(kCCDecrypt),
                                self.algorithm,
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBuffer.baseAddress,
                                key.count,
                                ivBuffer.baseAddress,
                                inputBuffer.baseAddress,
                                bytes.count,
                                outputBuffer.baseAddress,
                                outputCapacity,
                                &outputCount
                            )
                        }
                    }
                }
            }

            guard status == kCCSuccess else {
                if status == kCCDecodeError {
                    throw SSHAuthenticationMethodError.incorrectLegacyPrivateKeyPEMPassphrase(
                        pemType
                    )
                }
                throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
            }

            output.removeSubrange(outputCount..<output.count)
            return output
        }
    }
}
