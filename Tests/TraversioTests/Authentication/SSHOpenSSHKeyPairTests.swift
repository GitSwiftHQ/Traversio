// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(
    "Generated OpenSSH key pairs round-trip across supported algorithms",
    arguments: supportedKeyPairAlgorithmCases
)
func generatedOpenSSHKeyPairsRoundTripAcrossSupportedAlgorithms(
    _ testCase: OpenSSHKeyPairAlgorithmTestCase
) throws {
    let comment = "unit-test-\(testCase.name)"
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: testCase.algorithm,
        comment: comment
    )

    let expectedAuthorizedKeyLine = try authorizedKeyLine(
        for: keyPair.authenticationMethod,
        comment: comment
    )
    #expect(keyPair.algorithm == testCase.algorithm)
    #expect(keyPair.comment == comment)
    #expect(keyPair.privateKeyPEM.contains("BEGIN OPENSSH PRIVATE KEY"))
    #expect(keyPair.privateKeyPEM.contains("END OPENSSH PRIVATE KEY"))
    #expect(keyPair.authorizedKeyLine == expectedAuthorizedKeyLine)

    let parsedAuthenticationMethod = try authenticationMethod(
        for: testCase.algorithm,
        privateKeyPEM: keyPair.privateKeyPEM
    )
    #expect(parsedAuthenticationMethod == keyPair.authenticationMethod)

    if case let .rsa(bitCount) = testCase.algorithm {
        #expect(bitCountForRSAPrivateKey(keyPair.authenticationMethod) == bitCount)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(
    "Encrypted generated OpenSSH key pairs round-trip across supported algorithms",
    arguments: supportedKeyPairAlgorithmCases
)
func encryptedGeneratedOpenSSHKeyPairsRoundTripAcrossSupportedAlgorithms(
    _ testCase: OpenSSHKeyPairAlgorithmTestCase
) throws {
    let encryption = SSHOpenSSHPrivateKeyEncryption(
        passphrase: sampleGeneratedKeyPassphrase
    )
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: testCase.algorithm,
        comment: "encrypted-\(testCase.name)",
        encryption: encryption
    )

    let envelope = try parseEnvelopeHeader(from: keyPair.privateKeyPEM)
    #expect(envelope.cipherName == SSHOpenSSHPrivateKeyEncryption.Cipher.aes256CTR.rawValue)
    #expect(envelope.kdfName == "bcrypt")
    #expect(envelope.rounds == encryption.rounds)
    #expect(envelope.salt.count == 16)

    let parsedAuthenticationMethod = try authenticationMethod(
        for: testCase.algorithm,
        privateKeyPEM: keyPair.privateKeyPEM,
        passphrase: sampleGeneratedKeyPassphrase
    )
    #expect(parsedAuthenticationMethod == keyPair.authenticationMethod)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(
    "Generated OpenSSH private keys support every current AES export cipher",
    arguments: supportedPrivateKeyCipherCases
)
func generatedOpenSSHPrivateKeysSupportEveryCurrentAESExportCipher(
    _ testCase: OpenSSHPrivateKeyCipherTestCase
) throws {
    let encryption = SSHOpenSSHPrivateKeyEncryption(
        passphrase: sampleGeneratedKeyPassphrase,
        cipher: testCase.cipher,
        rounds: 32
    )
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: .ed25519,
        comment: "cipher-\(testCase.name)",
        encryption: encryption
    )

    let envelope = try parseEnvelopeHeader(from: keyPair.privateKeyPEM)
    #expect(envelope.cipherName == testCase.cipher.rawValue)
    #expect(envelope.kdfName == "bcrypt")
    #expect(envelope.rounds == 32)
    #expect(envelope.salt.count == 16)

    let parsedAuthenticationMethod = try SSHAuthenticationMethod.ed25519PrivateKey(
        openSSHPrivateKey: keyPair.privateKeyPEM,
        passphrase: sampleGeneratedKeyPassphrase
    )
    #expect(parsedAuthenticationMethod == keyPair.authenticationMethod)

    do {
        _ = try SSHAuthenticationMethod.ed25519PrivateKey(
            openSSHPrivateKey: keyPair.privateKeyPEM
        )
        Issue.record("Expected generated encrypted OpenSSH private key without a passphrase to fail")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .missingOpenSSHPrivateKeyPassphrase)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func generatedOpenSSHPrivateKeyEncryptionDefaultsMatchOpenSSHBaseline() throws {
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: .ed25519,
        comment: "default-encryption",
        encryption: SSHOpenSSHPrivateKeyEncryption(
            passphrase: sampleGeneratedKeyPassphrase
        )
    )

    let envelope = try parseEnvelopeHeader(from: keyPair.privateKeyPEM)
    #expect(envelope.cipherName == "aes256-ctr")
    #expect(envelope.kdfName == "bcrypt")
    #expect(envelope.rounds == 24)
    #expect(envelope.salt.count == 16)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func generatedOpenSSHKeyPairRejectsInvalidRSABitCount() throws {
    do {
        _ = try SSHOpenSSHKeyPair.generate(algorithm: .rsa(bitCount: 1537))
        Issue.record("Expected invalid RSA bit count to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .invalidOpenSSHRSAKeyBitCount(1537))
    }
}

#if os(macOS)
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(
    "Generated OpenSSH key pairs are readable by the system ssh-keygen tool",
    arguments: sshKeygenCompatibilityCases
)
func generatedOpenSSHKeyPairsAreReadableBySystemSSHKeygen(
    _ testCase: OpenSSHSSHKeygenCompatibilityTestCase
) throws {
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: testCase.algorithm,
        comment: testCase.name,
        encryption: testCase.encryption
    )
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKeyURL = temporaryDirectory.appendingPathComponent(testCase.name)
    try keyPair.privateKeyPEM.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: privateKeyURL.path
    )

    let output = try runSSHKeygen(
        privateKeyURL: privateKeyURL,
        passphrase: testCase.encryption?.passphrase
    )
    if output.exitStatus != 0 {
        Issue.record("ssh-keygen stderr: \(output.standardError)")
    }
    #expect(output.exitStatus == 0)
    #expect(authorizedKeyPrefix(output.standardOutput) == authorizedKeyPrefix(keyPair.authorizedKeyLine))
}
#endif

let sampleGeneratedKeyPassphrase = "generated-passphrase"

struct OpenSSHKeyPairAlgorithmTestCase: Sendable, CustomTestStringConvertible {
    let name: String
    let algorithm: SSHOpenSSHKeyPair.Algorithm

    var testDescription: String {
        self.name
    }
}

struct OpenSSHPrivateKeyCipherTestCase: Sendable, CustomTestStringConvertible {
    let name: String
    let cipher: SSHOpenSSHPrivateKeyEncryption.Cipher

    var testDescription: String {
        self.name
    }
}

struct OpenSSHSSHKeygenCompatibilityTestCase: Sendable, CustomTestStringConvertible {
    let name: String
    let algorithm: SSHOpenSSHKeyPair.Algorithm
    let encryption: SSHOpenSSHPrivateKeyEncryption?

    var testDescription: String {
        self.name
    }
}

let supportedKeyPairAlgorithmCases: [OpenSSHKeyPairAlgorithmTestCase] = [
    OpenSSHKeyPairAlgorithmTestCase(name: "ed25519", algorithm: .ed25519),
    OpenSSHKeyPairAlgorithmTestCase(name: "ecdsa-p256", algorithm: .ecdsaP256),
    OpenSSHKeyPairAlgorithmTestCase(name: "ecdsa-p384", algorithm: .ecdsaP384),
    OpenSSHKeyPairAlgorithmTestCase(name: "ecdsa-p521", algorithm: .ecdsaP521),
    OpenSSHKeyPairAlgorithmTestCase(name: "rsa-2048", algorithm: .rsa(bitCount: 2048)),
]

let supportedPrivateKeyCipherCases: [OpenSSHPrivateKeyCipherTestCase] = [
    OpenSSHPrivateKeyCipherTestCase(name: "aes128-ctr", cipher: .aes128CTR),
    OpenSSHPrivateKeyCipherTestCase(name: "aes192-ctr", cipher: .aes192CTR),
    OpenSSHPrivateKeyCipherTestCase(name: "aes256-ctr", cipher: .aes256CTR),
    OpenSSHPrivateKeyCipherTestCase(name: "aes128-cbc", cipher: .aes128CBC),
    OpenSSHPrivateKeyCipherTestCase(name: "aes192-cbc", cipher: .aes192CBC),
    OpenSSHPrivateKeyCipherTestCase(name: "aes256-cbc", cipher: .aes256CBC),
]

let sshKeygenCompatibilityCases: [OpenSSHSSHKeygenCompatibilityTestCase] = [
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-ed25519",
        algorithm: .ed25519,
        encryption: nil
    ),
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-ed25519-encrypted",
        algorithm: .ed25519,
        encryption: SSHOpenSSHPrivateKeyEncryption(passphrase: sampleGeneratedKeyPassphrase)
    ),
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-ecdsa-p256",
        algorithm: .ecdsaP256,
        encryption: nil
    ),
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-ecdsa-p384",
        algorithm: .ecdsaP384,
        encryption: nil
    ),
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-ecdsa-p521",
        algorithm: .ecdsaP521,
        encryption: nil
    ),
    OpenSSHSSHKeygenCompatibilityTestCase(
        name: "ssh-keygen-rsa-2048",
        algorithm: .rsa(bitCount: 2048),
        encryption: nil
    ),
]

private struct OpenSSHPrivateKeyEnvelopeHeader {
    let cipherName: String
    let kdfName: String
    let rounds: UInt32
    let salt: [UInt8]
}

private func authenticationMethod(
    for algorithm: SSHOpenSSHKeyPair.Algorithm,
    privateKeyPEM: String,
    passphrase: String? = nil
) throws -> SSHAuthenticationMethod {
    switch algorithm {
    case .ed25519:
        return try SSHAuthenticationMethod.ed25519PrivateKey(
            openSSHPrivateKey: privateKeyPEM,
            passphrase: passphrase
        )
    case .ecdsaP256, .ecdsaP384, .ecdsaP521:
        return try SSHAuthenticationMethod.ecdsaPrivateKey(
            openSSHPrivateKey: privateKeyPEM,
            passphrase: passphrase
        )
    case .rsa:
        return try SSHAuthenticationMethod.rsaPrivateKey(
            openSSHPrivateKey: privateKeyPEM,
            passphrase: passphrase
        )
    }
}

private func authorizedKeyLine(
    for authenticationMethod: SSHAuthenticationMethod,
    comment: String
) throws -> String {
    switch authenticationMethod {
    case let .ed25519PrivateKey(rawRepresentation):
        return try SSHEd25519PrivateKey(
            rawRepresentation: rawRepresentation
        ).authorizedKeyLine(comment: comment)
    case let .ecdsaP256PrivateKey(rawRepresentation):
        return try SSHECDSAPrivateKey.nistp256(
            rawRepresentation: rawRepresentation
        ).authorizedKeyLine(comment: comment)
    case let .ecdsaP384PrivateKey(rawRepresentation):
        return try SSHECDSAPrivateKey.nistp384(
            rawRepresentation: rawRepresentation
        ).authorizedKeyLine(comment: comment)
    case let .ecdsaP521PrivateKey(rawRepresentation):
        return try SSHECDSAPrivateKey.nistp521(
            rawRepresentation: rawRepresentation
        ).authorizedKeyLine(comment: comment)
    case let .rsaPrivateKey(pkcs1DERRepresentation):
        return try SSHRSAPrivateKey(
            pkcs1DERRepresentation: pkcs1DERRepresentation
        ).authorizedKeyLine(comment: comment)
    case .password, .passwordWithChangeResponse, .publicKey, .keyboardInteractive:
        Issue.record("Unexpected authentication method in generated key-pair test")
        throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
    }
}

private func bitCountForRSAPrivateKey(_ authenticationMethod: SSHAuthenticationMethod) -> Int {
    guard case let .rsaPrivateKey(pkcs1DERRepresentation) = authenticationMethod,
          let components = try? SSHRSAPKCS1DERCodec.parsePrivateKey(pkcs1DERRepresentation) else {
        return 0
    }

    let modulus = components.modulus
    guard let firstNonZeroIndex = modulus.firstIndex(where: { $0 != 0 }) else {
        return 0
    }

    let significantBytes = modulus[firstNonZeroIndex...]
    let leadingZeroBits = significantBytes.first?.leadingZeroBitCount ?? 0
    return significantBytes.count * 8 - leadingZeroBits
}

private func parseEnvelopeHeader(
    from privateKeyPEM: String
) throws -> OpenSSHPrivateKeyEnvelopeHeader {
    let lines = privateKeyPEM
        .split(whereSeparator: \.isNewline)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    guard lines.count >= 3,
          let encodedPayload = Data(base64Encoded: lines.dropFirst().dropLast().joined()) else {
        throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKeyPEM
    }

    var reader = SSHWireReader(bytes: Array(encodedPayload))
    let magic = try reader.readRawBytes(count: Array("openssh-key-v1".utf8).count + 1)
    guard magic == Array("openssh-key-v1".utf8) + [0] else {
        throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
    }

    let cipherName = try reader.readUTF8String()
    let kdfName = try reader.readUTF8String()
    let kdfOptions = try reader.readString()
    let keyCount = try reader.readUInt32()
    guard keyCount == 1 else {
        throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
    }

    if kdfName == "none" {
        return OpenSSHPrivateKeyEnvelopeHeader(
            cipherName: cipherName,
            kdfName: kdfName,
            rounds: 0,
            salt: []
        )
    }

    var kdfReader = SSHWireReader(bytes: kdfOptions)
    let salt = try kdfReader.readString()
    let rounds = try kdfReader.readUInt32()
    guard kdfReader.isAtEnd else {
        throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
    }

    return OpenSSHPrivateKeyEnvelopeHeader(
        cipherName: cipherName,
        kdfName: kdfName,
        rounds: rounds,
        salt: salt
    )
}

private struct SSHKeygenOutput {
    let exitStatus: Int32
    let standardOutput: String
    let standardError: String
}

private func authorizedKeyPrefix(_ line: String) -> String {
    line
        .split(whereSeparator: \.isWhitespace)
        .prefix(2)
        .joined(separator: " ")
}

#if os(macOS)
private func runSSHKeygen(
    privateKeyURL: URL,
    passphrase: String?
) throws -> SSHKeygenOutput {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    var arguments = ["-y", "-f", privateKeyURL.path]
    if let passphrase {
        arguments += ["-P", passphrase]
    }
    task.arguments = arguments

    let standardOutput = Pipe()
    let standardError = Pipe()
    task.standardOutput = standardOutput
    task.standardError = standardError
    try task.run()
    task.waitUntilExit()

    return SSHKeygenOutput(
        exitStatus: task.terminationStatus,
        standardOutput: String(
            decoding: standardOutput.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        ).trimmingCharacters(in: .whitespacesAndNewlines),
        standardError: String(
            decoding: standardError.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        ).trimmingCharacters(in: .whitespacesAndNewlines)
    )
}
#endif
