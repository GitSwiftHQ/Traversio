// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

/// Errors raised while parsing authentication inputs such as OpenSSH private
/// keys or keyboard-interactive responses.
public enum SSHAuthenticationMethodError: Error, Equatable, Sendable {
    /// Invalid private key PEM.
    case invalidPrivateKeyPEM
    /// Invalid OpenSSH Private Key PEM.
    case invalidOpenSSHPrivateKeyPEM
    /// Invalid OpenSSH Private Key.
    case invalidOpenSSHPrivateKey
    /// Invalid RSA Private Key PEM.
    case invalidRSAPrivateKeyPEM
    /// Invalid OpenSSHRSA Key Bit Count.
    case invalidOpenSSHRSAKeyBitCount(Int)
    /// Unsupported private key PEM type.
    case unsupportedPrivateKeyPEMType(String)
    /// Encrypted legacy private key PEM is unsupported.
    case encryptedLegacyPrivateKeyPEMUnsupported(String)
    /// Missing encrypted legacy private key PEM passphrase.
    case missingLegacyPrivateKeyPEMPassphrase(String)
    /// Incorrect encrypted legacy private key PEM passphrase.
    case incorrectLegacyPrivateKeyPEMPassphrase(String)
    /// Unsupported encrypted legacy private key PEM cipher.
    case unsupportedLegacyPrivateKeyPEMCipher(String)
    /// Missing OpenSSH Private Key Passphrase.
    case missingOpenSSHPrivateKeyPassphrase
    /// Incorrect OpenSSH Private Key Passphrase.
    case incorrectOpenSSHPrivateKeyPassphrase
    /// Unsupported OpenSSH Private Key Cipher.
    case unsupportedOpenSSHPrivateKeyCipher(String)
    /// Unsupported OpenSSH Private Key KDF.
    case unsupportedOpenSSHPrivateKeyKDF(String)
    /// Unsupported OpenSSH Private Key Count.
    case unsupportedOpenSSHPrivateKeyCount(UInt32)
    /// Unsupported OpenSSH Private Key Type.
    case unsupportedOpenSSHPrivateKeyType(String)
    /// Invalid keyboard-interactive Response Count.
    case invalidKeyboardInteractiveResponseCount(expected: Int, received: Int)
    /// Empty public key Authentication Algorithm List.
    case emptyPublicKeyAuthenticationAlgorithmList
    /// Empty public key Authentication public key.
    case emptyPublicKeyAuthenticationPublicKey
}

extension SSHAuthenticationMethodError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidPrivateKeyPEM:
            return "The private key PEM is malformed."
        case .invalidOpenSSHPrivateKeyPEM:
            return "The text is not a valid OpenSSH private-key PEM. Expected -----BEGIN OPENSSH PRIVATE KEY-----."
        case .invalidOpenSSHPrivateKey:
            return "The OpenSSH private key is malformed or does not match its public key."
        case .invalidRSAPrivateKeyPEM:
            return "The RSA private-key PEM is malformed or does not contain a valid PKCS#1 RSA private key."
        case let .invalidOpenSSHRSAKeyBitCount(bitCount):
            return "The OpenSSH RSA private-key bit count is unsupported: \(bitCount)."
        case let .unsupportedPrivateKeyPEMType(type):
            return "Unsupported private-key PEM type: \(type). Supported types are OPENSSH PRIVATE KEY, unencrypted PRIVATE KEY, RSA PRIVATE KEY, and unencrypted EC PRIVATE KEY."
        case let .encryptedLegacyPrivateKeyPEMUnsupported(type):
            return "Encrypted OpenSSL-style private-key PEM is not supported for \(type). Traversio supports passphrases for traditional RSA PRIVATE KEY PEM; convert this container to encrypted OpenSSH format or provide an unencrypted supported PEM."
        case let .missingLegacyPrivateKeyPEMPassphrase(type):
            return "The encrypted legacy \(type) PEM requires a passphrase."
        case let .incorrectLegacyPrivateKeyPEMPassphrase(type):
            return "The encrypted legacy \(type) PEM could not be decrypted with the supplied passphrase, or the decrypted key data is malformed."
        case let .unsupportedLegacyPrivateKeyPEMCipher(cipher):
            return "Unsupported encrypted legacy private-key PEM cipher: \(cipher)."
        case .missingOpenSSHPrivateKeyPassphrase:
            return "The encrypted OpenSSH private key requires a passphrase."
        case .incorrectOpenSSHPrivateKeyPassphrase:
            return "The OpenSSH private-key passphrase is incorrect."
        case let .unsupportedOpenSSHPrivateKeyCipher(cipher):
            return "Unsupported OpenSSH private-key cipher: \(cipher)."
        case let .unsupportedOpenSSHPrivateKeyKDF(kdf):
            return "Unsupported OpenSSH private-key KDF: \(kdf)."
        case let .unsupportedOpenSSHPrivateKeyCount(count):
            return "Unsupported OpenSSH private-key count: \(count). Traversio expects one private key per PEM."
        case let .unsupportedOpenSSHPrivateKeyType(type):
            return "Unsupported OpenSSH private-key type: \(type)."
        case let .invalidKeyboardInteractiveResponseCount(expected, received):
            return "Invalid keyboard-interactive response count: expected \(expected), received \(received)."
        case .emptyPublicKeyAuthenticationAlgorithmList:
            return "The public-key authentication algorithm list is empty."
        case .emptyPublicKeyAuthenticationPublicKey:
            return "The public-key authentication key is empty."
        }
    }
}

private struct SSHPrivateKeyPEMBlock {
    let type: String
    let headers: [String]
    let derBytes: [UInt8]

    var isLegacyEncrypted: Bool {
        self.headers.contains { header in
            header.lowercased().hasPrefix("proc-type:")
                && header.localizedCaseInsensitiveContains("encrypted")
        } || self.headers.contains { header in
            header.lowercased().hasPrefix("dek-info:")
        }
    }
}

private enum SSHPrivateKeyPEMParser {
    static func firstType(in pem: String) -> String? {
        self.normalizedLines(in: pem).first.flatMap(self.type(fromBeginMarker:))
    }

    static func parse(_ pem: String) throws -> SSHPrivateKeyPEMBlock {
        let lines = self.normalizedLines(in: pem)
        guard lines.count >= 3,
              let type = self.type(fromBeginMarker: lines[0]),
              lines.last == self.endMarker(for: type) else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        let payloadLines = Array(lines.dropFirst().dropLast())
        var headerLines: [String] = []
        var bodyStartIndex = payloadLines.startIndex
        while bodyStartIndex < payloadLines.endIndex,
              payloadLines[bodyStartIndex].contains(":") {
            headerLines.append(payloadLines[bodyStartIndex])
            bodyStartIndex = payloadLines.index(after: bodyStartIndex)
        }

        let bodyLines = payloadLines[bodyStartIndex...]
        guard bodyLines.isEmpty == false,
              bodyLines.allSatisfy({ !$0.contains(":") }) else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        guard let der = Data(base64Encoded: bodyLines.joined()) else {
            throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
        }

        return SSHPrivateKeyPEMBlock(
            type: type,
            headers: headerLines,
            derBytes: Array(der)
        )
    }

    private static func normalizedLines(in pem: String) -> [String] {
        pem
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.isEmpty == false }
    }

    private static func type(fromBeginMarker marker: String) -> String? {
        let prefix = "-----BEGIN "
        let suffix = "-----"
        guard marker.hasPrefix(prefix), marker.hasSuffix(suffix) else {
            return nil
        }

        return String(marker.dropFirst(prefix.count).dropLast(suffix.count))
    }

    private static func endMarker(for type: String) -> String {
        "-----END \(type)-----"
    }
}

private enum SSHPrivateKeyDERError: Error {
    case invalidDER
}

private struct SSHPrivateKeyDERReader {
    private let bytes: [UInt8]
    private var readIndex: Int = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool {
        self.readIndex == self.bytes.count
    }

    var nextTag: UInt8? {
        guard self.readIndex < self.bytes.count else {
            return nil
        }
        return self.bytes[self.readIndex]
    }

    mutating func readElement(tag expectedTag: UInt8) throws -> [UInt8] {
        let actualTag = try self.readByte()
        guard actualTag == expectedTag else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let length = try self.readLength()
        return try self.readBytes(count: length)
    }

    mutating func readIntegerValue() throws -> Int {
        let bytes = try self.readElement(tag: 0x02)
        guard bytes.isEmpty == false,
              bytes.count <= MemoryLayout<Int>.size,
              bytes[0] & 0x80 == 0 else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        return bytes.reduce(0) { ($0 << 8) | Int($1) }
    }

    mutating func readObjectIdentifier() throws -> String {
        let bytes = try self.readElement(tag: 0x06)
        guard let first = bytes.first else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        var components: [UInt64] = [
            UInt64(first / 40),
            UInt64(first % 40),
        ]
        var value: UInt64 = 0
        var hasContinuation = false

        for byte in bytes.dropFirst() {
            hasContinuation = true
            value = (value << 7) | UInt64(byte & 0x7f)
            if byte & 0x80 == 0 {
                components.append(value)
                value = 0
                hasContinuation = false
            }
        }

        guard !hasContinuation else {
            throw SSHPrivateKeyDERError.invalidDER
        }
        return components.map(String.init).joined(separator: ".")
    }

    mutating func readOptionalNull() throws {
        guard self.nextTag == 0x05 else {
            return
        }
        let nullPayload = try self.readElement(tag: 0x05)
        guard nullPayload.isEmpty else {
            throw SSHPrivateKeyDERError.invalidDER
        }
    }

    private mutating func readByte() throws -> UInt8 {
        let bytes = try self.readBytes(count: 1)
        return bytes[0]
    }

    private mutating func readLength() throws -> Int {
        let first = try self.readByte()
        if first & 0x80 == 0 {
            return Int(first)
        }

        let byteCount = Int(first & 0x7f)
        guard byteCount > 0, byteCount <= 4 else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let bytes = try self.readBytes(count: byteCount)
        guard bytes.first != 0 else {
            throw SSHPrivateKeyDERError.invalidDER
        }
        return bytes.reduce(0) { ($0 << 8) | Int($1) }
    }

    private mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0,
              self.readIndex + count <= self.bytes.count else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let result = Array(self.bytes[self.readIndex..<self.readIndex + count])
        self.readIndex += count
        return result
    }
}

private enum SSHPrivateKeyPKCS8Parser {
    private static let rsaEncryptionOID = "1.2.840.113549.1.1.1"
    private static let ecPublicKeyOID = "1.2.840.10045.2.1"
    private static let ed25519OID = "1.3.101.112"
    private static let p256OID = "1.2.840.10045.3.1.7"
    private static let p384OID = "1.3.132.0.34"
    private static let p521OID = "1.3.132.0.35"

    private enum Algorithm: Equatable {
        case rsa
        case ed25519
        case ecdsa(SSHECDSACurve)
    }

    static func authenticationMethod(derBytes: [UInt8]) throws -> SSHAuthenticationMethod {
        let parsed = try self.parsePrivateKeyInfo(derBytes)
        switch parsed.algorithm {
        case .rsa:
            let privateKey = try SSHRSAPrivateKey(
                pkcs1DERRepresentation: parsed.privateKeyBytes
            )
            return .rsaPrivateKey(
                pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
            )
        case .ed25519:
            return .ed25519PrivateKey(
                rawRepresentation: try self.parseEd25519Seed(parsed.privateKeyBytes)
            )
        case let .ecdsa(curve):
            return try self.authenticationMethod(
                ecPrivateKeyDER: parsed.privateKeyBytes,
                expectedCurve: curve
            )
        }
    }

    static func authenticationMethod(
        ecPrivateKeyDER: [UInt8],
        expectedCurve: SSHECDSACurve?
    ) throws -> SSHAuthenticationMethod {
        let parsed = try self.parseECPrivateKey(ecPrivateKeyDER)
        let curve = try self.requireCurve(parsed.curve ?? expectedCurve)
        if let expectedCurve, parsed.curve.map({ $0 != expectedCurve }) ?? false {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let rawRepresentation = try self.normalizedECPrivateScalar(
            parsed.privateScalar,
            curve: curve
        )
        switch SSHECDSAPrivateKey(curve: curve, rawRepresentation: rawRepresentation) {
        case let .nistp256(rawRepresentation):
            _ = try P256.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
            return .ecdsaP256PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp384(rawRepresentation):
            _ = try P384.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
            return .ecdsaP384PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp521(rawRepresentation):
            _ = try P521.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
            return .ecdsaP521PrivateKey(rawRepresentation: rawRepresentation)
        }
    }

    private static func parsePrivateKeyInfo(
        _ derBytes: [UInt8]
    ) throws -> (algorithm: Algorithm, privateKeyBytes: [UInt8]) {
        var outerReader = SSHPrivateKeyDERReader(bytes: derBytes)
        var reader = SSHPrivateKeyDERReader(
            bytes: try outerReader.readElement(tag: 0x30)
        )
        guard outerReader.isAtEnd,
              try reader.readIntegerValue() == 0 else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let algorithm = try self.parseAlgorithmIdentifier(
            try reader.readElement(tag: 0x30)
        )
        let privateKeyBytes = try reader.readElement(tag: 0x04)
        while reader.nextTag == 0xa0 || reader.nextTag == 0xa1 {
            _ = try reader.readElement(tag: reader.nextTag!)
        }
        guard reader.isAtEnd else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        return (algorithm, privateKeyBytes)
    }

    private static func parseAlgorithmIdentifier(_ bytes: [UInt8]) throws -> Algorithm {
        var reader = SSHPrivateKeyDERReader(bytes: bytes)
        let oid = try reader.readObjectIdentifier()

        switch oid {
        case Self.rsaEncryptionOID:
            try reader.readOptionalNull()
            guard reader.isAtEnd else {
                throw SSHPrivateKeyDERError.invalidDER
            }
            return .rsa
        case Self.ed25519OID:
            guard reader.isAtEnd else {
                throw SSHPrivateKeyDERError.invalidDER
            }
            return .ed25519
        case Self.ecPublicKeyOID:
            let curveOID = try reader.readObjectIdentifier()
            guard reader.isAtEnd else {
                throw SSHPrivateKeyDERError.invalidDER
            }
            return .ecdsa(try self.curve(for: curveOID))
        default:
            throw SSHAuthenticationMethodError.unsupportedPrivateKeyPEMType("PRIVATE KEY")
        }
    }

    private static func parseEd25519Seed(_ privateKeyBytes: [UInt8]) throws -> [UInt8] {
        var reader = SSHPrivateKeyDERReader(bytes: privateKeyBytes)
        if let seed = try? reader.readElement(tag: 0x04),
           reader.isAtEnd,
           seed.count == 32 {
            return seed
        }

        guard privateKeyBytes.count == 32 else {
            throw SSHPrivateKeyDERError.invalidDER
        }
        return privateKeyBytes
    }

    private static func parseECPrivateKey(
        _ derBytes: [UInt8]
    ) throws -> (privateScalar: [UInt8], curve: SSHECDSACurve?) {
        var outerReader = SSHPrivateKeyDERReader(bytes: derBytes)
        var reader = SSHPrivateKeyDERReader(
            bytes: try outerReader.readElement(tag: 0x30)
        )
        guard outerReader.isAtEnd,
              try reader.readIntegerValue() == 1 else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        let privateScalar = try reader.readElement(tag: 0x04)
        var curve: SSHECDSACurve?
        while !reader.isAtEnd {
            switch reader.nextTag {
            case 0xa0:
                curve = try self.parseExplicitECCurveParameters(
                    try reader.readElement(tag: 0xa0)
                )
            case 0xa1:
                _ = try reader.readElement(tag: 0xa1)
            default:
                throw SSHPrivateKeyDERError.invalidDER
            }
        }

        return (privateScalar, curve)
    }

    private static func parseExplicitECCurveParameters(_ bytes: [UInt8]) throws -> SSHECDSACurve {
        var reader = SSHPrivateKeyDERReader(bytes: bytes)
        let oid = try reader.readObjectIdentifier()
        guard reader.isAtEnd else {
            throw SSHPrivateKeyDERError.invalidDER
        }
        return try self.curve(for: oid)
    }

    private static func requireCurve(_ curve: SSHECDSACurve?) throws -> SSHECDSACurve {
        guard let curve else {
            throw SSHPrivateKeyDERError.invalidDER
        }
        return curve
    }

    private static func curve(for oid: String) throws -> SSHECDSACurve {
        switch oid {
        case Self.p256OID:
            return .nistp256
        case Self.p384OID:
            return .nistp384
        case Self.p521OID:
            return .nistp521
        default:
            throw SSHAuthenticationMethodError.unsupportedPrivateKeyPEMType("EC PRIVATE KEY")
        }
    }

    private static func normalizedECPrivateScalar(
        _ scalar: [UInt8],
        curve: SSHECDSACurve
    ) throws -> [UInt8] {
        let magnitude = Array(scalar.drop { $0 == 0 })
        guard magnitude.isEmpty == false,
              magnitude.count <= curve.coordinateByteCount else {
            throw SSHPrivateKeyDERError.invalidDER
        }

        return Array(repeating: 0, count: curve.coordinateByteCount - magnitude.count) + magnitude
    }
}

private enum SSHOpenSSHPrivateKeyParser {
    private struct ParsedPrivateKeyEnvelope {
        let publicKeyBlob: [UInt8]
        let privateKeyBlock: [UInt8]
        let isEncrypted: Bool
    }

    private struct ParsedOpenSSHECDSAPublicKey {
        let curve: SSHECDSACurve
        let publicKey: [UInt8]
    }

    private struct ParsedOpenSSHRSAPublicKey {
        let modulus: [UInt8]
        let publicExponent: [UInt8]
        let publicKeyBlob: [UInt8]
    }

    static func parseEd25519PrivateKey(
        pem: String,
        passphrase: String? = nil
    ) throws -> SSHEd25519PrivateKey {
        let encodedPayload = try self.decodePEMForAuthentication(pem)
        return try self.parseEd25519PrivateKey(
            encodedPayload: encodedPayload,
            passphrase: passphrase
        )
    }

    static func parseECDSAPrivateKey(
        pem: String,
        passphrase: String? = nil
    ) throws -> SSHECDSAPrivateKey {
        let encodedPayload = try self.decodePEMForAuthentication(pem)
        return try self.parseECDSAPrivateKey(
            encodedPayload: encodedPayload,
            passphrase: passphrase
        )
    }

    static func parseRSAPrivateKey(
        pem: String,
        passphrase: String? = nil
    ) throws -> SSHRSAPrivateKey {
        let encodedPayload = try self.decodePEMForAuthentication(pem)
        return try self.parseRSAPrivateKey(
            encodedPayload: encodedPayload,
            passphrase: passphrase
        )
    }

    private static func decodePEMForAuthentication(_ pem: String) throws -> [UInt8] {
        do {
            return try SSHOpenSSHPrivateKeyEnvelopeParser.decodePEM(pem)
        } catch let error as SSHOpenSSHPrivateKeyInfoError {
            throw self.authenticationError(for: error)
        }
    }

    private static func parseEd25519PrivateKey(
        encodedPayload: [UInt8],
        passphrase: String?
    ) throws -> SSHEd25519PrivateKey {
        do {
            let envelope = try self.parseEnvelope(
                encodedPayload,
                passphrase: passphrase
            )
            let publicKey = try self.parseEd25519PublicKey(from: envelope.publicKeyBlob)
            return try self.parseEd25519PrivateKey(
                privateKeyBlock: envelope.privateKeyBlock,
                expectedPublicKey: publicKey,
                isEncrypted: envelope.isEncrypted
            )
        } catch let error as SSHAuthenticationMethodError {
            throw error
        } catch {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
    }

    private static func parseECDSAPrivateKey(
        encodedPayload: [UInt8],
        passphrase: String?
    ) throws -> SSHECDSAPrivateKey {
        do {
            let envelope = try self.parseEnvelope(
                encodedPayload,
                passphrase: passphrase
            )
            let publicKey = try self.parseECDSAPublicKey(from: envelope.publicKeyBlob)
            return try self.parseECDSAPrivateKey(
                privateKeyBlock: envelope.privateKeyBlock,
                expectedPublicKey: publicKey,
                isEncrypted: envelope.isEncrypted
            )
        } catch let error as SSHAuthenticationMethodError {
            throw error
        } catch {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
    }

    private static func parseRSAPrivateKey(
        encodedPayload: [UInt8],
        passphrase: String?
    ) throws -> SSHRSAPrivateKey {
        do {
            let envelope = try self.parseEnvelope(
                encodedPayload,
                passphrase: passphrase
            )
            let publicKey = try self.parseRSAPublicKey(from: envelope.publicKeyBlob)
            return try self.parseRSAPrivateKey(
                privateKeyBlock: envelope.privateKeyBlock,
                expectedPublicKey: publicKey,
                isEncrypted: envelope.isEncrypted
            )
        } catch let error as SSHAuthenticationMethodError {
            throw error
        } catch let error as SSHRSAPrivateKeyError {
            switch error {
            case .unsupportedSignatureAlgorithm:
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            case .invalidPKCS1PrivateKey, .invalidRSAPrivateKey:
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            }
        } catch {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
    }

    private static func parseEnvelope(
        _ encodedPayload: [UInt8],
        passphrase: String?
    ) throws -> ParsedPrivateKeyEnvelope {
        let envelope: SSHOpenSSHPrivateKeyEnvelope
        do {
            envelope = try SSHOpenSSHPrivateKeyEnvelopeParser.parseEnvelope(encodedPayload)
        } catch let error as SSHOpenSSHPrivateKeyInfoError {
            throw self.authenticationError(for: error)
        }

        let cipher = try SSHOpenSSHPrivateKeyCipher(name: envelope.cipherName)
        let kdf = try SSHOpenSSHPrivateKeyKDF(
            name: envelope.kdfName,
            options: envelope.kdfOptions
        )

        guard envelope.keyCount == 1 else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyCount(
                envelope.keyCount
            )
        }

        guard (cipher == .none) == (kdf == .none) else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
        if kdf == .none, envelope.kdfOptions.isEmpty == false {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        let derivedKey = try kdf.deriveKeyMaterial(
            passphrase: passphrase,
            byteCount: cipher.keyByteCount + cipher.ivByteCount
        )
        let privateKeyBlock = try cipher.decrypt(
            encryptedPrivateKeyBlock: envelope.privateKeyBlock,
            using: derivedKey
        )

        return ParsedPrivateKeyEnvelope(
            publicKeyBlob: envelope.publicKeyBlobs[0],
            privateKeyBlock: privateKeyBlock,
            isEncrypted: cipher.isEncrypted
        )
    }

    private static func parseEd25519PublicKey(from publicKeyBlob: [UInt8]) throws -> [UInt8] {
        var reader = SSHWireReader(bytes: publicKeyBlob)
        let keyType = try reader.readUTF8String()
        guard keyType == "ssh-ed25519" else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let publicKey = try reader.readString()
        guard publicKey.count == 32, reader.isAtEnd else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return publicKey
    }

    private static func parseECDSAPublicKey(
        from publicKeyBlob: [UInt8]
    ) throws -> ParsedOpenSSHECDSAPublicKey {
        var reader = SSHWireReader(bytes: publicKeyBlob)
        let keyType = try reader.readUTF8String()
        guard let curve = SSHECDSACurve(algorithmName: keyType) else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let curveName = try reader.readUTF8String()
        let publicKey = try reader.readString()

        guard curve.rawValue == curveName,
              reader.isAtEnd else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        switch curve {
        case .nistp256:
            _ = try P256.Signing.PublicKey(x963Representation: Data(publicKey))
        case .nistp384:
            _ = try P384.Signing.PublicKey(x963Representation: Data(publicKey))
        case .nistp521:
            _ = try P521.Signing.PublicKey(x963Representation: Data(publicKey))
        }

        return ParsedOpenSSHECDSAPublicKey(curve: curve, publicKey: publicKey)
    }

    private static func parseRSAPublicKey(
        from publicKeyBlob: [UInt8]
    ) throws -> ParsedOpenSSHRSAPublicKey {
        var reader = SSHWireReader(bytes: publicKeyBlob)
        let keyType = try reader.readUTF8String()
        guard keyType == "ssh-rsa" else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let publicExponent = try self.decodeUnsignedMPInt(reader.readMPInt())
        let modulus = try self.decodeUnsignedMPInt(reader.readMPInt())

        guard !publicExponent.isEmpty,
              !modulus.isEmpty,
              reader.isAtEnd else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return ParsedOpenSSHRSAPublicKey(
            modulus: modulus,
            publicExponent: publicExponent,
            publicKeyBlob: publicKeyBlob
        )
    }

    private static func parseEd25519PrivateKey(
        privateKeyBlock: [UInt8],
        expectedPublicKey: [UInt8],
        isEncrypted: Bool
    ) throws -> SSHEd25519PrivateKey {
        var reader = SSHWireReader(bytes: privateKeyBlock)
        let check1 = try reader.readUInt32()
        let check2 = try reader.readUInt32()
        try self.requireMatchingCheckints(check1, check2, isEncrypted: isEncrypted)

        let keyType = try reader.readUTF8String()
        guard keyType == "ssh-ed25519" else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let publicKey = try reader.readString()
        let privateAndPublicKey = try reader.readString()
        _ = try reader.readString() // comment
        let padding = try reader.readRawBytes(count: reader.remainingByteCount)

        guard publicKey == expectedPublicKey,
              publicKey.count == 32,
              privateAndPublicKey.count == 64 else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        let embeddedPublicKey = Array(privateAndPublicKey.suffix(32))
        guard embeddedPublicKey == publicKey else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        try self.requireValidPadding(padding)
        return try SSHEd25519PrivateKey(
            rawRepresentation: Array(privateAndPublicKey.prefix(32))
        )
    }

    private static func parseECDSAPrivateKey(
        privateKeyBlock: [UInt8],
        expectedPublicKey: ParsedOpenSSHECDSAPublicKey,
        isEncrypted: Bool
    ) throws -> SSHECDSAPrivateKey {
        var reader = SSHWireReader(bytes: privateKeyBlock)
        let check1 = try reader.readUInt32()
        let check2 = try reader.readUInt32()
        try self.requireMatchingCheckints(check1, check2, isEncrypted: isEncrypted)

        let keyType = try reader.readUTF8String()
        guard keyType == expectedPublicKey.curve.algorithmName else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let curveName = try reader.readUTF8String()
        let publicKey = try reader.readString()
        let privateScalar = try reader.readMPInt()
        _ = try reader.readString() // comment
        let padding = try reader.readRawBytes(count: reader.remainingByteCount)

        guard curveName == expectedPublicKey.curve.rawValue,
              publicKey == expectedPublicKey.publicKey else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        try self.requireValidPadding(padding)

        let rawRepresentation = try self.decodeECDSAPrivateScalar(
            privateScalar,
            coordinateByteCount: expectedPublicKey.curve.coordinateByteCount
        )
        let privateKey = SSHECDSAPrivateKey(
            curve: expectedPublicKey.curve,
            rawRepresentation: rawRepresentation
        )
        try privateKey.validatePublicKeyMatches(expectedPublicKey.publicKey)
        return privateKey
    }

    private static func parseRSAPrivateKey(
        privateKeyBlock: [UInt8],
        expectedPublicKey: ParsedOpenSSHRSAPublicKey,
        isEncrypted: Bool
    ) throws -> SSHRSAPrivateKey {
        var reader = SSHWireReader(bytes: privateKeyBlock)
        let check1 = try reader.readUInt32()
        let check2 = try reader.readUInt32()
        try self.requireMatchingCheckints(check1, check2, isEncrypted: isEncrypted)

        let keyType = try reader.readUTF8String()
        guard keyType == "ssh-rsa" else {
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(keyType)
        }

        let modulus = try self.decodeUnsignedMPInt(reader.readMPInt())
        let publicExponent = try self.decodeUnsignedMPInt(reader.readMPInt())
        let privateExponent = try self.decodeUnsignedMPInt(reader.readMPInt())
        let coefficient = try self.decodeUnsignedMPInt(reader.readMPInt())
        let prime1 = try self.decodeUnsignedMPInt(reader.readMPInt())
        let prime2 = try self.decodeUnsignedMPInt(reader.readMPInt())
        _ = try reader.readString() // comment
        let padding = try reader.readRawBytes(count: reader.remainingByteCount)

        guard modulus == expectedPublicKey.modulus,
              publicExponent == expectedPublicKey.publicExponent else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        try self.requireValidPadding(padding)

        let exponent1 = try SSHRSAUnsignedInteger.mod(
            privateExponent,
            by: SSHRSAUnsignedInteger.subtractOne(prime1)
        )
        let exponent2 = try SSHRSAUnsignedInteger.mod(
            privateExponent,
            by: SSHRSAUnsignedInteger.subtractOne(prime2)
        )
        let derRepresentation = SSHRSAPKCS1DERCodec.encodePrivateKey(
            modulus: modulus,
            publicExponent: publicExponent,
            privateExponent: privateExponent,
            prime1: prime1,
            prime2: prime2,
            exponent1: exponent1,
            exponent2: exponent2,
            coefficient: coefficient
        )
        let privateKey = try SSHRSAPrivateKey(
            pkcs1DERRepresentation: derRepresentation
        )
        guard privateKey.publicKeyBlob == expectedPublicKey.publicKeyBlob else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return privateKey
    }

    private static func decodeECDSAPrivateScalar(
        _ scalar: SSHMPInt,
        coordinateByteCount: Int
    ) throws -> [UInt8] {
        let encodedScalar = scalar.encodedBytes
        let magnitude: [UInt8]

        if encodedScalar.first == 0 {
            magnitude = Array(encodedScalar.dropFirst())
        } else {
            magnitude = encodedScalar
        }

        guard !magnitude.isEmpty,
              magnitude.count <= coordinateByteCount else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return Array(repeating: 0, count: coordinateByteCount - magnitude.count) + magnitude
    }

    private static func decodeUnsignedMPInt(_ value: SSHMPInt) throws -> [UInt8] {
        let magnitude = value.encodedBytes.first == 0
            ? Array(value.encodedBytes.dropFirst())
            : value.encodedBytes
        guard !magnitude.isEmpty else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return magnitude
    }

    private static func requireMatchingCheckints(
        _ first: UInt32,
        _ second: UInt32,
        isEncrypted: Bool
    ) throws {
        guard first == second else {
            if isEncrypted {
                throw SSHAuthenticationMethodError.incorrectOpenSSHPrivateKeyPassphrase
            }
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
    }

    private static func requireValidPadding(_ padding: [UInt8]) throws {
        for (offset, byte) in padding.enumerated() {
            guard byte == UInt8(offset + 1) else {
                throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
            }
        }
    }

    static func authenticationError(
        for error: SSHOpenSSHPrivateKeyInfoError
    ) -> SSHAuthenticationMethodError {
        switch error {
        case .invalidPEM, .invalidBase64:
            return .invalidOpenSSHPrivateKeyPEM
        case let .invalidKeyCount(keyCount):
            return .unsupportedOpenSSHPrivateKeyCount(keyCount)
        case .invalidMagic, .invalidEnvelope, .invalidKDFOptions, .invalidPublicKey:
            return .invalidOpenSSHPrivateKey
        }
    }
}
extension SSHEd25519PrivateKey {
    init(openSSHPrivateKey pem: String, passphrase: String? = nil) throws {
        self = try SSHOpenSSHPrivateKeyParser.parseEd25519PrivateKey(
            pem: pem,
            passphrase: passphrase
        )
    }

    static func loadOpenSSHPrivateKey(
        from path: String,
        passphrase: String? = nil
    ) throws -> SSHEd25519PrivateKey {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try SSHEd25519PrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
    }
}
extension SSHECDSAPrivateKey {
    init(openSSHPrivateKey pem: String, passphrase: String? = nil) throws {
        self = try SSHOpenSSHPrivateKeyParser.parseECDSAPrivateKey(
            pem: pem,
            passphrase: passphrase
        )
    }

    static func loadOpenSSHPrivateKey(
        from path: String,
        passphrase: String? = nil
    ) throws -> SSHECDSAPrivateKey {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try SSHECDSAPrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
    }
}
extension SSHRSAPrivateKey {
    init(openSSHPrivateKey pem: String, passphrase: String? = nil) throws {
        self = try SSHOpenSSHPrivateKeyParser.parseRSAPrivateKey(
            pem: pem,
            passphrase: passphrase
        )
    }

    static func loadOpenSSHPrivateKey(
        from path: String,
        passphrase: String? = nil
    ) throws -> SSHRSAPrivateKey {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try SSHRSAPrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
    }
}

public extension SSHAuthenticationMethod {
    /// Parses a private-key PEM string and returns the matching authentication
    /// method.
    ///
    /// This broad loader accepts OpenSSH `openssh-key-v1` private keys and
    /// OpenSSL-style PKCS#8 Ed25519/RSA/ECDSA, traditional RSA, and
    /// traditional EC private keys. Traditional RSA PEM may be unencrypted or
    /// passphrase-encrypted with a supported OpenSSL legacy PEM cipher.
    static func privateKeyPEM(
        _ pem: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        if SSHPrivateKeyPEMParser.firstType(in: pem) == "OPENSSH PRIVATE KEY" {
            return try .openSSHPrivateKey(pem, passphrase: passphrase)
        }

        let block = try SSHPrivateKeyPEMParser.parse(pem)
        switch block.type {
        case "PRIVATE KEY":
            do {
                return try SSHPrivateKeyPKCS8Parser.authenticationMethod(
                    derBytes: block.derBytes
                )
            } catch let error as SSHAuthenticationMethodError {
                throw error
            } catch {
                throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
            }
        case "ENCRYPTED PRIVATE KEY":
            throw SSHAuthenticationMethodError.encryptedLegacyPrivateKeyPEMUnsupported(
                block.type
            )
        case "RSA PRIVATE KEY":
            let derBytes: [UInt8]
            let wasEncrypted = block.isLegacyEncrypted
            if wasEncrypted {
                derBytes = try SSHLegacyPrivateKeyPEMDecryption.decrypt(
                    encryptedDERBytes: block.derBytes,
                    headers: block.headers,
                    passphrase: passphrase,
                    pemType: block.type
                )
            } else {
                derBytes = block.derBytes
            }
            do {
                let privateKey = try SSHRSAPrivateKey(
                    pkcs1DERRepresentation: derBytes
                )
                return .rsaPrivateKey(
                    pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
                )
            } catch {
                if wasEncrypted {
                    throw SSHAuthenticationMethodError.incorrectLegacyPrivateKeyPEMPassphrase(
                        block.type
                    )
                }
                throw SSHAuthenticationMethodError.invalidRSAPrivateKeyPEM
            }
        case "EC PRIVATE KEY":
            guard !block.isLegacyEncrypted else {
                throw SSHAuthenticationMethodError.encryptedLegacyPrivateKeyPEMUnsupported(
                    block.type
                )
            }
            do {
                return try SSHPrivateKeyPKCS8Parser.authenticationMethod(
                    ecPrivateKeyDER: block.derBytes,
                    expectedCurve: nil
                )
            } catch let error as SSHAuthenticationMethodError {
                throw error
            } catch {
                throw SSHAuthenticationMethodError.invalidPrivateKeyPEM
            }
        case let type:
            throw SSHAuthenticationMethodError.unsupportedPrivateKeyPEMType(type)
        }
    }

    /// Loads a private-key PEM file and returns the matching authentication
    /// method.
    ///
    /// This broad loader accepts OpenSSH `openssh-key-v1` private keys and
    /// OpenSSH private keys, OpenSSL-style PKCS#8 keys, traditional RSA keys,
    /// and traditional EC keys. Traditional RSA PEM may be unencrypted or
    /// passphrase-encrypted with a supported OpenSSL legacy PEM cipher.
    static func privateKeyPEM(
        contentsOfFile path: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try .privateKeyPEM(pem, passphrase: passphrase)
    }

    /// Parses an OpenSSH private key string and returns the matching
    /// authentication method.
    ///
    /// Ed25519, ECDSA, and RSA OpenSSH private keys are auto-detected.
    static func openSSHPrivateKey(
        _ pem: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let info: SSHOpenSSHPrivateKeyInfo
        do {
            info = try SSHOpenSSHPrivateKeyInfo.parse(pem)
        } catch let error as SSHOpenSSHPrivateKeyInfoError {
            throw SSHOpenSSHPrivateKeyParser.authenticationError(for: error)
        }

        switch info.primaryPublicKey.algorithm {
        case .ed25519:
            return try .ed25519PrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
        case .ecdsa:
            return try .ecdsaPrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
        case .rsa:
            return try .rsaPrivateKey(openSSHPrivateKey: pem, passphrase: passphrase)
        case let .certificate(algorithmName, _), let .unknown(algorithmName):
            throw SSHAuthenticationMethodError.unsupportedOpenSSHPrivateKeyType(algorithmName)
        }
    }

    /// Loads an OpenSSH private key file and returns the matching
    /// authentication method.
    ///
    /// Example:
    ///
    /// ```swift
    /// let auth = try SSHAuthenticationMethod.openSSHPrivateKey(
    ///     contentsOfFile: "/Users/me/.ssh/id_ed25519"
    /// )
    /// ```
    static func openSSHPrivateKey(
        contentsOfFile path: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try .openSSHPrivateKey(pem, passphrase: passphrase)
    }

    /// Parses an OpenSSH Ed25519 private key.
    static func ed25519PrivateKey(
        openSSHPrivateKey pem: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let privateKey = try SSHEd25519PrivateKey(
            openSSHPrivateKey: pem,
            passphrase: passphrase
        )
        return .ed25519PrivateKey(rawRepresentation: privateKey.rawRepresentation)
    }

    /// Loads an OpenSSH Ed25519 private key file.
    static func ed25519PrivateKey(
        contentsOfOpenSSHPrivateKeyFile path: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let privateKey = try SSHEd25519PrivateKey.loadOpenSSHPrivateKey(
            from: path,
            passphrase: passphrase
        )
        return .ed25519PrivateKey(rawRepresentation: privateKey.rawRepresentation)
    }

    /// Parses an OpenSSH ECDSA private key.
    static func ecdsaPrivateKey(
        openSSHPrivateKey pem: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        switch try SSHECDSAPrivateKey(
            openSSHPrivateKey: pem,
            passphrase: passphrase
        ) {
        case let .nistp256(rawRepresentation):
            return .ecdsaP256PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp384(rawRepresentation):
            return .ecdsaP384PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp521(rawRepresentation):
            return .ecdsaP521PrivateKey(rawRepresentation: rawRepresentation)
        }
    }

    /// Loads an OpenSSH ECDSA private key file.
    static func ecdsaPrivateKey(
        contentsOfOpenSSHPrivateKeyFile path: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let privateKey = try SSHECDSAPrivateKey.loadOpenSSHPrivateKey(
            from: path,
            passphrase: passphrase
        )
        switch privateKey {
        case let .nistp256(rawRepresentation):
            return .ecdsaP256PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp384(rawRepresentation):
            return .ecdsaP384PrivateKey(rawRepresentation: rawRepresentation)
        case let .nistp521(rawRepresentation):
            return .ecdsaP521PrivateKey(rawRepresentation: rawRepresentation)
        }
    }

    /// Parses an OpenSSH RSA private key.
    static func rsaPrivateKey(
        openSSHPrivateKey pem: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let privateKey = try SSHRSAPrivateKey(
            openSSHPrivateKey: pem,
            passphrase: passphrase
        )
        return .rsaPrivateKey(pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation)
    }

    /// Loads an OpenSSH RSA private key file.
    static func rsaPrivateKey(
        contentsOfOpenSSHPrivateKeyFile path: String,
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let privateKey = try SSHRSAPrivateKey.loadOpenSSHPrivateKey(
            from: path,
            passphrase: passphrase
        )
        return .rsaPrivateKey(pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation)
    }
}
