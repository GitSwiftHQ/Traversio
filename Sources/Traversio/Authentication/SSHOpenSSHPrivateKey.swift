// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

/// Errors raised while parsing authentication inputs such as OpenSSH private
/// keys or keyboard-interactive responses.
public enum SSHAuthenticationMethodError: Error, Equatable, Sendable {
    /// Invalid OpenSSH Private Key PEM.
    case invalidOpenSSHPrivateKeyPEM
    /// Invalid OpenSSH Private Key.
    case invalidOpenSSHPrivateKey
    /// Invalid OpenSSHRSA Key Bit Count.
    case invalidOpenSSHRSAKeyBitCount(Int)
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
