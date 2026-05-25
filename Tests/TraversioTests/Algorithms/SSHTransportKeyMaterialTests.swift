// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverProducesExpectedMaterialForFixedInputs() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let sharedSecret = SSHMPInt(unsignedMagnitude: Array(0x01...0x20))
    let exchangeHash = (0xa0...0xbf).map(UInt8.init)
    let sessionIdentifier = (0xc0...0xdf).map(UInt8.init)

    let material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: sharedSecret,
        exchangeHash: exchangeHash,
        sessionIdentifier: sessionIdentifier
    )

    #expect(
        material.initialIVClientToServer
            == [202, 215, 144, 237, 55, 228, 115, 218, 250, 35, 39, 238, 77, 191, 219, 70]
    )
    #expect(
        material.initialIVServerToClient
            == [20, 124, 208, 84, 223, 54, 231, 19, 240, 201, 109, 171, 31, 26, 159, 237]
    )
    #expect(
        material.encryptionKeyClientToServer
            == [68, 169, 246, 198, 103, 241, 240, 89, 97, 130, 37, 188, 114, 209, 185, 43]
    )
    #expect(
        material.encryptionKeyServerToClient
            == [102, 64, 196, 234, 87, 103, 216, 42, 89, 5, 95, 80, 214, 3, 157, 65, 41, 122, 53, 185, 65, 114, 45, 37, 220, 190, 178, 147, 98, 27, 80, 227]
    )
    #expect(
        material.integrityKeyClientToServer
            == [130, 55, 242, 220, 242, 247, 167, 139, 153, 255, 180, 50, 245, 187, 139, 163, 113, 26, 104, 239, 154, 146, 32, 192, 159, 132, 69, 8, 174, 40, 142, 37]
    )
    #expect(
        material.integrityKeyServerToClient
            == [144, 145, 162, 36, 138, 180, 223, 199, 64, 56, 220, 253, 242, 117, 130, 146, 12, 20, 194, 156, 45, 107, 110, 60, 226, 43, 243, 173, 46, 233, 224, 81, 70, 133, 223, 42, 183, 219, 219, 219, 196, 211, 99, 107, 76, 199, 62, 14, 199, 100, 104, 59, 245, 241, 36, 22, 249, 248, 223, 124, 149, 210, 72, 72]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverUsesCurveSpecificHashForNISTP384AndP521() throws {
    let sharedSecret = SSHMPInt(unsignedMagnitude: Array(0x01...0x20))
    let p384ExchangeHash = (0xa0...0xcf).map(UInt8.init)
    let p384SessionIdentifier = (0x20...0x4f).map(UInt8.init)
    let p521ExchangeHash = (0x80...0xbf).map(UInt8.init)
    let p521SessionIdentifier = (0x30...0x6f).map(UInt8.init)

    let p384Material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: makeNegotiatedAlgorithms(
            keyExchangeAlgorithm: "ecdh-sha2-nistp384"
        ),
        sharedSecret: sharedSecret,
        exchangeHash: p384ExchangeHash,
        sessionIdentifier: p384SessionIdentifier
    )
    let p521Material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: makeNegotiatedAlgorithms(
            keyExchangeAlgorithm: "ecdh-sha2-nistp521"
        ),
        sharedSecret: sharedSecret,
        exchangeHash: p521ExchangeHash,
        sessionIdentifier: p521SessionIdentifier
    )

    #expect(
        p384Material.initialIVClientToServer
            == deriveExpectedKey(
                sharedSecret: sharedSecret,
                exchangeHash: p384ExchangeHash,
                prefix: 0x41,
                sessionIdentifier: p384SessionIdentifier,
                length: 16,
                hashFunction: .sha384
            )
    )
    #expect(
        p521Material.initialIVClientToServer
            == deriveExpectedKey(
                sharedSecret: sharedSecret,
                exchangeHash: p521ExchangeHash,
                prefix: 0x41,
                sessionIdentifier: p521SessionIdentifier,
                length: 16,
                hashFunction: .sha512
            )
    )
    #expect(p384Material.integrityKeyServerToClient.count == 64)
    #expect(p521Material.integrityKeyServerToClient.count == 64)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverRejectsUnsupportedEncryptionAlgorithm() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes192-ctr",
        encryptionAlgorithmServerToClient: "aes128-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-256",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    do {
        _ = try SSHTransportKeyDeriver().deriveKeys(
            negotiatedAlgorithms: negotiatedAlgorithms,
            sharedSecret: SSHMPInt(unsignedMagnitude: [0x01]),
            exchangeHash: Array(repeating: 0x02, count: 32),
            sessionIdentifier: Array(repeating: 0x03, count: 32)
        )
        Issue.record("Expected unsupported-encryption-algorithm error")
    } catch {
        #expect(
            error as? SSHTransportKeyDerivationError
                == .unsupportedEncryptionAlgorithm("aes192-ctr")
        )
    }
}

private func makeNegotiatedAlgorithms(keyExchangeAlgorithm: String) -> SSHNegotiatedAlgorithms {
    SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: keyExchangeAlgorithm,
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
}

private func deriveExpectedKey(
    sharedSecret: SSHMPInt,
    exchangeHash: [UInt8],
    prefix: UInt8,
    sessionIdentifier: [UInt8],
    length: Int,
    hashFunction: ExpectedKDFHashFunction
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(mpint: sharedSecret)
    writer.write(rawBytes: exchangeHash)
    let basePrefix = writer.bytes
    var material = hashFunction.hash(basePrefix + [prefix] + sessionIdentifier)

    while material.count < length {
        material += hashFunction.hash(basePrefix + material)
    }

    return Array(material.prefix(length))
}

private enum ExpectedKDFHashFunction {
    case sha384
    case sha512

    func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .sha384:
            return Array(SHA384.hash(data: bytes))
        case .sha512:
            return Array(SHA512.hash(data: bytes))
        }
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverAcceptsOpenSSHEncryptThenMacAlgorithms() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256-etm@openssh.com",
        macAlgorithmServerToClient: "hmac-sha2-512-etm@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    let material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )

    #expect(material.integrityKeyClientToServer.count == 32)
    #expect(material.integrityKeyServerToClient.count == 64)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverAcceptsOpenSSHUMACAlgorithms() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "umac-64-etm@openssh.com",
        macAlgorithmServerToClient: "umac-128@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    let material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )

    #expect(material.integrityKeyClientToServer.count == 16)
    #expect(material.integrityKeyServerToClient.count == 16)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverAcceptsOpenSSHAESGCMAlgorithms() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-gcm@openssh.com",
        encryptionAlgorithmServerToClient: "aes256-gcm@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    let material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )

    #expect(material.initialIVClientToServer.count == 12)
    #expect(material.initialIVServerToClient.count == 12)
    #expect(material.encryptionKeyClientToServer.count == 16)
    #expect(material.encryptionKeyServerToClient.count == 32)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportKeyDeriverAcceptsOpenSSHChaCha20Poly1305Algorithm() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "chacha20-poly1305@openssh.com",
        encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    let material = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )

    #expect(material.initialIVClientToServer.isEmpty)
    #expect(material.initialIVServerToClient.isEmpty)
    #expect(material.encryptionKeyClientToServer.count == 64)
    #expect(material.encryptionKeyServerToClient.count == 64)
}
