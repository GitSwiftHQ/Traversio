// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func curve25519KeyExchangeCompletesDeterministicallyForFixedInputs() throws {
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let serverIdentification = try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    let clientKeyPair = try makeCurve25519KeyPair(
        privateKeyBytes: Array(0x01...0x20)
    )
    let serverPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.rawRepresentation)
    let clientKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x00...0x0f)
    )
    let serverKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x10...0x1f)
    )
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0xde, 0xad, 0xbe, 0xef]

    let result = try SSHCurve25519KeyExchange().completeClientKeyExchange(
        keyExchangeAlgorithm: "curve25519-sha256",
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        clientKeyPair: clientKeyPair,
        serverHostKey: serverHostKey,
        serverEphemeralPublicKey: serverPublicKey,
        serverSignature: serverSignature
    )

    let expectedSharedSecretBytes = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(clientKeyPair.privateKey)
    ).sharedSecretFromKeyAgreement(
        with: serverPrivateKey.publicKey
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: clientKeyPair.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret,
        hashAlgorithm: .sha256
    )

    #expect(result.clientEphemeralPublicKey == clientKeyPair.publicKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.serverHostKey == serverHostKey)
    #expect(result.serverSignature == serverSignature)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
    #expect(result.sessionIdentifier == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func curve25519KeyExchangeRejectsInvalidRemotePublicKeyLength() throws {
    let keyPair = try makeCurve25519KeyPair(privateKeyBytes: Array(0x01...0x20))

    do {
        _ = try SSHCurve25519KeyExchange().completeClientKeyExchange(
            keyExchangeAlgorithm: "curve25519-sha256",
            clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
            serverIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
            clientKeyExchangeInitPayload: [0x14],
            serverKeyExchangeInitPayload: [0x14],
            clientKeyPair: keyPair,
            serverHostKey: [],
            serverEphemeralPublicKey: [0x01, 0x02],
            serverSignature: []
        )
        Issue.record("Expected invalid-remote-public-key-length error")
    } catch {
        #expect(
            error as? SSHCurve25519KeyExchangeError
                == .invalidRemotePublicKeyLength(2)
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func nistp256KeyExchangeCompletesDeterministicallyForFixedInputs() throws {
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let serverIdentification = try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    let clientKeyPair = try makeNISTP256KeyPair(
        privateKeyBytes: Array(0x01...0x20)
    )
    let serverPrivateKey = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.x963Representation)
    let clientKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256"]
    )
    let serverKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256"]
    )
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0xca, 0xfe, 0xba, 0xbe]

    let result = try SSHCurve25519KeyExchange().completeClientKeyExchange(
        keyExchangeAlgorithm: "ecdh-sha2-nistp256",
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        clientKeyPair: clientKeyPair,
        serverHostKey: serverHostKey,
        serverEphemeralPublicKey: serverPublicKey,
        serverSignature: serverSignature
    )

    let expectedSharedSecretBytes = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: Data(clientKeyPair.privateKey)
    ).sharedSecretFromKeyAgreement(
        with: serverPrivateKey.publicKey
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: clientKeyPair.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret,
        hashAlgorithm: .sha256
    )

    #expect(result.keyExchangeAlgorithm == "ecdh-sha2-nistp256")
    #expect(result.clientEphemeralPublicKey == clientKeyPair.publicKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.serverHostKey == serverHostKey)
    #expect(result.serverSignature == serverSignature)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
    #expect(result.sessionIdentifier == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func nistp384KeyExchangeCompletesWithSHA384Transcript() throws {
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let serverIdentification = try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    let clientKeyPair = try makeNISTP384KeyPair(
        privateKeyBytes: makeFixedScalarBytes(length: 48, scalar: 1)
    )
    let serverPrivateKey = try P384.KeyAgreement.PrivateKey(
        rawRepresentation: Data(makeFixedScalarBytes(length: 48, scalar: 2))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.x963Representation)
    let clientKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp384"]
    )
    let serverKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp384"]
    )
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0x38, 0x40]

    let result = try SSHCurve25519KeyExchange().completeClientKeyExchange(
        keyExchangeAlgorithm: "ecdh-sha2-nistp384",
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        clientKeyPair: clientKeyPair,
        serverHostKey: serverHostKey,
        serverEphemeralPublicKey: serverPublicKey,
        serverSignature: serverSignature
    )

    let expectedSharedSecretBytes = try P384.KeyAgreement.PrivateKey(
        rawRepresentation: Data(clientKeyPair.privateKey)
    ).sharedSecretFromKeyAgreement(
        with: serverPrivateKey.publicKey
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: clientKeyPair.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret,
        hashAlgorithm: .sha384
    )

    #expect(result.keyExchangeAlgorithm == "ecdh-sha2-nistp384")
    #expect(result.clientEphemeralPublicKey == clientKeyPair.publicKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
    #expect(result.exchangeHash.count == 48)
    #expect(result.sessionIdentifier == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func nistp521KeyExchangeCompletesWithSHA512Transcript() throws {
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let serverIdentification = try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    let clientKeyPair = try makeNISTP521KeyPair(
        privateKeyBytes: makeFixedScalarBytes(length: 66, scalar: 1)
    )
    let serverPrivateKey = try P521.KeyAgreement.PrivateKey(
        rawRepresentation: Data(makeFixedScalarBytes(length: 66, scalar: 2))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.x963Representation)
    let clientKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp521"]
    )
    let serverKEXINITPayload = try makeKeyExchangeInitPayload(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp521"]
    )
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0x52, 0x10]

    let result = try SSHCurve25519KeyExchange().completeClientKeyExchange(
        keyExchangeAlgorithm: "ecdh-sha2-nistp521",
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        clientKeyPair: clientKeyPair,
        serverHostKey: serverHostKey,
        serverEphemeralPublicKey: serverPublicKey,
        serverSignature: serverSignature
    )

    let expectedSharedSecretBytes = try P521.KeyAgreement.PrivateKey(
        rawRepresentation: Data(clientKeyPair.privateKey)
    ).sharedSecretFromKeyAgreement(
        with: serverPrivateKey.publicKey
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: serverIdentification,
        clientKeyExchangeInitPayload: clientKEXINITPayload,
        serverKeyExchangeInitPayload: serverKEXINITPayload,
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: clientKeyPair.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret,
        hashAlgorithm: .sha512
    )

    #expect(result.keyExchangeAlgorithm == "ecdh-sha2-nistp521")
    #expect(result.clientEphemeralPublicKey == clientKeyPair.publicKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
    #expect(result.exchangeHash.count == 64)
    #expect(result.sessionIdentifier == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func ellipticCurveKeyExchangeGeneratesExpectedPublicKeySizes() throws {
    let keyExchange = SSHCurve25519KeyExchange()

    #expect(try keyExchange.generateKeyPair(keyExchangeAlgorithm: "ecdh-sha2-nistp256").publicKey.count == 65)
    #expect(try keyExchange.generateKeyPair(keyExchangeAlgorithm: "ecdh-sha2-nistp384").publicKey.count == 97)
    #expect(try keyExchange.generateKeyPair(keyExchangeAlgorithm: "ecdh-sha2-nistp521").publicKey.count == 133)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeCurve25519KeyPair(privateKeyBytes: [UInt8]) throws -> SSHCurve25519KeyPair {
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(privateKeyBytes)
    )

    return SSHCurve25519KeyPair(
        privateKey: privateKeyBytes,
        publicKey: Array(privateKey.publicKey.rawRepresentation)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeNISTP256KeyPair(privateKeyBytes: [UInt8]) throws -> SSHCurve25519KeyPair {
    let privateKey = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: Data(privateKeyBytes)
    )

    return SSHCurve25519KeyPair(
        privateKey: privateKeyBytes,
        publicKey: Array(privateKey.publicKey.x963Representation)
    )
}

private func makeKeyExchangeInitPayload(
    cookie: [UInt8],
    keyExchangeAlgorithms: [String] = ["curve25519-sha256"]
) throws -> [UInt8] {
    try SSHTransportMessageSerializer().serialize(
        .keyExchangeInit(
            SSHKeyExchangeInitMessage(
                cookie: cookie,
                keyExchangeAlgorithms: keyExchangeAlgorithms,
                serverHostKeyAlgorithms: ["ssh-ed25519"],
                encryptionAlgorithmsClientToServer: ["aes128-ctr"],
                encryptionAlgorithmsServerToClient: ["aes128-ctr"],
                macAlgorithmsClientToServer: ["hmac-sha2-256"],
                macAlgorithmsServerToClient: ["hmac-sha2-256"],
                compressionAlgorithmsClientToServer: ["none"],
                compressionAlgorithmsServerToClient: ["none"]
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeNISTP384KeyPair(privateKeyBytes: [UInt8]) throws -> SSHCurve25519KeyPair {
    let privateKey = try P384.KeyAgreement.PrivateKey(
        rawRepresentation: Data(privateKeyBytes)
    )

    return SSHCurve25519KeyPair(
        privateKey: privateKeyBytes,
        publicKey: Array(privateKey.publicKey.x963Representation)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeNISTP521KeyPair(privateKeyBytes: [UInt8]) throws -> SSHCurve25519KeyPair {
    let privateKey = try P521.KeyAgreement.PrivateKey(
        rawRepresentation: Data(privateKeyBytes)
    )

    return SSHCurve25519KeyPair(
        privateKey: privateKeyBytes,
        publicKey: Array(privateKey.publicKey.x963Representation)
    )
}

private func makeFixedScalarBytes(length: Int, scalar: UInt8) -> [UInt8] {
    Array(repeating: UInt8(0), count: length - 1) + [scalar]
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeExpectedExchangeHash(
    clientIdentification: SSHIdentification,
    serverIdentification: SSHIdentification,
    clientKeyExchangeInitPayload: [UInt8],
    serverKeyExchangeInitPayload: [UInt8],
    serverHostKey: [UInt8],
    clientEphemeralPublicKey: [UInt8],
    serverEphemeralPublicKey: [UInt8],
    sharedSecret: SSHMPInt,
    hashAlgorithm: ExpectedExchangeHashAlgorithm
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: clientIdentification.rawValue)
    writer.write(utf8: serverIdentification.rawValue)
    writer.write(string: clientKeyExchangeInitPayload)
    writer.write(string: serverKeyExchangeInitPayload)
    writer.write(string: serverHostKey)
    writer.write(string: clientEphemeralPublicKey)
    writer.write(string: serverEphemeralPublicKey)
    writer.write(mpint: sharedSecret)
    return hashAlgorithm.hash(writer.bytes)
}

private enum ExpectedExchangeHashAlgorithm {
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
