// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

enum SSHTransportKeyDerivationError: Error, Equatable, Sendable {
    case unsupportedKeyExchangeAlgorithm(String)
    case unsupportedEncryptionAlgorithm(String)
    case unsupportedMACAlgorithm(String)
}

package struct SSHTransportKeyMaterial: Equatable, Sendable {
    let initialIVClientToServer: [UInt8]
    let initialIVServerToClient: [UInt8]
    let encryptionKeyClientToServer: [UInt8]
    let encryptionKeyServerToClient: [UInt8]
    let integrityKeyClientToServer: [UInt8]
    let integrityKeyServerToClient: [UInt8]
}
package struct SSHTransportKeyDeriver: Sendable {
    func deriveKeys(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        sharedSecret: SSHMPInt,
        exchangeHash: [UInt8],
        sessionIdentifier: [UInt8]
    ) throws -> SSHTransportKeyMaterial {
        let hashFunction = try self.hashFunction(
            keyExchangeAlgorithm: negotiatedAlgorithms.keyExchangeAlgorithm
        )
        let clientToServerCipher = try self.cipherProfile(
            algorithm: negotiatedAlgorithms.encryptionAlgorithmClientToServer
        )
        let serverToClientCipher = try self.cipherProfile(
            algorithm: negotiatedAlgorithms.encryptionAlgorithmServerToClient
        )
        let clientToServerMAC = try self.macProfile(
            algorithm: negotiatedAlgorithms.macAlgorithmClientToServer
        )
        let serverToClientMAC = try self.macProfile(
            algorithm: negotiatedAlgorithms.macAlgorithmServerToClient
        )

        return SSHTransportKeyMaterial(
            initialIVClientToServer: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x41,
                sessionIdentifier: sessionIdentifier,
                length: clientToServerCipher.ivLength,
                hashFunction: hashFunction
            ),
            initialIVServerToClient: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x42,
                sessionIdentifier: sessionIdentifier,
                length: serverToClientCipher.ivLength,
                hashFunction: hashFunction
            ),
            encryptionKeyClientToServer: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x43,
                sessionIdentifier: sessionIdentifier,
                length: clientToServerCipher.keyLength,
                hashFunction: hashFunction
            ),
            encryptionKeyServerToClient: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x44,
                sessionIdentifier: sessionIdentifier,
                length: serverToClientCipher.keyLength,
                hashFunction: hashFunction
            ),
            integrityKeyClientToServer: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x45,
                sessionIdentifier: sessionIdentifier,
                length: clientToServerMAC.keyLength,
                hashFunction: hashFunction
            ),
            integrityKeyServerToClient: try self.deriveKey(
                sharedSecret: sharedSecret,
                exchangeHash: exchangeHash,
                prefix: 0x46,
                sessionIdentifier: sessionIdentifier,
                length: serverToClientMAC.keyLength,
                hashFunction: hashFunction
            )
        )
    }

    private func deriveKey(
        sharedSecret: SSHMPInt,
        exchangeHash: [UInt8],
        prefix: UInt8,
        sessionIdentifier: [UInt8],
        length: Int,
        hashFunction: SSHHashFunction
    ) throws -> [UInt8] {
        let basePrefix = self.basePrefix(
            sharedSecret: sharedSecret,
            exchangeHash: exchangeHash
        )
        var material = hashFunction.hash(basePrefix + [prefix] + sessionIdentifier)

        while material.count < length {
            material += hashFunction.hash(basePrefix + material)
        }

        return Array(material.prefix(length))
    }

    private func basePrefix(sharedSecret: SSHMPInt, exchangeHash: [UInt8]) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(mpint: sharedSecret)
        writer.write(rawBytes: exchangeHash)
        return writer.bytes
    }

    private func hashFunction(keyExchangeAlgorithm: String) throws -> SSHHashFunction {
        switch keyExchangeAlgorithm {
        case "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256":
            return .sha256
        case "ecdh-sha2-nistp384":
            return .sha384
        case "ecdh-sha2-nistp521":
            return .sha512
        default:
            throw SSHTransportKeyDerivationError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }
    }

    private func cipherProfile(algorithm: String) throws -> SSHCipherProfile {
        switch algorithm {
        case "aes128-ctr":
            return SSHCipherProfile(ivLength: 16, keyLength: 16)
        case "aes256-ctr":
            return SSHCipherProfile(ivLength: 16, keyLength: 32)
        case "aes128-gcm@openssh.com":
            return SSHCipherProfile(ivLength: 12, keyLength: 16)
        case "aes256-gcm@openssh.com":
            return SSHCipherProfile(ivLength: 12, keyLength: 32)
        case "chacha20-poly1305@openssh.com":
            return SSHCipherProfile(ivLength: 0, keyLength: 64)
        default:
            throw SSHTransportKeyDerivationError.unsupportedEncryptionAlgorithm(
                algorithm
            )
        }
    }

    private func macProfile(algorithm: String) throws -> SSHMACProfile {
        switch algorithm {
        case "hmac-sha2-256", "hmac-sha2-256-etm@openssh.com":
            return SSHMACProfile(keyLength: 32)
        case "hmac-sha2-512", "hmac-sha2-512-etm@openssh.com":
            return SSHMACProfile(keyLength: 64)
        case "umac-64@openssh.com", "umac-64-etm@openssh.com",
            "umac-128@openssh.com", "umac-128-etm@openssh.com":
            return SSHMACProfile(keyLength: 16)
        default:
            throw SSHTransportKeyDerivationError.unsupportedMACAlgorithm(
                algorithm
            )
        }
    }
}

private struct SSHCipherProfile: Equatable, Sendable {
    let ivLength: Int
    let keyLength: Int
}

private struct SSHMACProfile: Equatable, Sendable {
    let keyLength: Int
}
private enum SSHHashFunction: Sendable {
    case sha256
    case sha384
    case sha512

    func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .sha256:
            return Array(SHA256.hash(data: bytes))
        case .sha384:
            return Array(SHA384.hash(data: bytes))
        case .sha512:
            return Array(SHA512.hash(data: bytes))
        }
    }
}
