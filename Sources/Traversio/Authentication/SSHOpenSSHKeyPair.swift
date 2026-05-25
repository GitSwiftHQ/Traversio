// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Security

/// Encryption settings for generated OpenSSH private-key PEM output.
public struct SSHOpenSSHPrivateKeyEncryption: Equatable, Sendable {
    /// OpenSSH private-key encryption cipher.
    public enum Cipher: String, Equatable, Sendable {
        /// Aes128 CTR.
        case aes128CTR = "aes128-ctr"
        /// Aes192 CTR.
        case aes192CTR = "aes192-ctr"
        /// Aes256 CTR.
        case aes256CTR = "aes256-ctr"
        /// Aes128 CBC.
        case aes128CBC = "aes128-cbc"
        /// Aes192 CBC.
        case aes192CBC = "aes192-cbc"
        /// Aes256 CBC.
        case aes256CBC = "aes256-cbc"
    }

    private static let defaultRounds: UInt32 = 24
/// Passphrase.

    /// Private-key encryption passphrase.
    public let passphrase: String
    /// Private-key encryption cipher.
    public let cipher: Cipher
    /// Bcrypt KDF rounds.
    public let rounds: UInt32
    /// Creates an SSHOpenSSHPrivateKeyEncryption.

    public init(
        passphrase: String,
        cipher: Cipher = .aes256CTR,
        rounds: UInt32 = 24
    ) {
        self.passphrase = passphrase
        self.cipher = cipher
        self.rounds = rounds == 0 ? Self.defaultRounds : rounds
    }
}
/// Generated OpenSSH key pair material.
///
/// The value includes a Traversio authentication method, a private-key PEM
/// string for storage, and an `authorized_keys` line for installing on a server.
public struct SSHOpenSSHKeyPair: Equatable, Sendable {
    /// Key algorithm to generate.
    public enum Algorithm: Equatable, Sendable {
        /// Ed25519.
        case ed25519
        /// ECDSA P256.
        case ecdsaP256
        /// ECDSA P384.
        case ecdsaP384
        /// ECDSA P521.
        case ecdsaP521
        /// RSA.
        case rsa(bitCount: Int)
    }
/// Algorithm.

    /// Algorithm.
    public let algorithm: Algorithm
    /// OpenSSH key comment.
    public let comment: String
    /// Authentication Method.
    public let authenticationMethod: SSHAuthenticationMethod
    /// OpenSSH private-key PEM text.
    public let privateKeyPEM: String
    /// Line suitable for an authorized_keys file.
    public let authorizedKeyLine: String

    /// Generates a new key pair.
    ///
    /// Example:
    ///
    /// ```swift
    /// let keyPair = try SSHOpenSSHKeyPair.generate(algorithm: .ed25519)
    /// print(keyPair.authorizedKeyLine)
    /// ```
    public static func generate(
        algorithm: Algorithm,
        comment: String = "traversio",
        encryption: SSHOpenSSHPrivateKeyEncryption? = nil
    ) throws -> SSHOpenSSHKeyPair {
        let privateKey = try SSHOpenSSHGeneratedPrivateKey.generate(
            algorithm: algorithm
        )
        return try SSHOpenSSHKeyPair(
            algorithm: privateKey.algorithm,
            comment: comment,
            authenticationMethod: privateKey.authenticationMethod,
            privateKeyPEM: SSHOpenSSHPrivateKeySerializer.serialize(
                privateKey: privateKey,
                comment: comment,
                encryption: encryption
            ),
            authorizedKeyLine: privateKey.authorizedKeyLine(comment: comment)
        )
    }
}
private enum SSHOpenSSHGeneratedPrivateKey {
    case ed25519(SSHEd25519PrivateKey)
    case ecdsa(SSHECDSAPrivateKey)
    case rsa(SSHRSAPrivateKey)

    static func generate(
        algorithm: SSHOpenSSHKeyPair.Algorithm
    ) throws -> SSHOpenSSHGeneratedPrivateKey {
        switch algorithm {
        case .ed25519:
            return .ed25519(SSHEd25519PrivateKey())
        case .ecdsaP256:
            let privateKey = P256.Signing.PrivateKey()
            return .ecdsa(
                .nistp256(rawRepresentation: Array(privateKey.rawRepresentation))
            )
        case .ecdsaP384:
            let privateKey = P384.Signing.PrivateKey()
            return .ecdsa(
                .nistp384(rawRepresentation: Array(privateKey.rawRepresentation))
            )
        case .ecdsaP521:
            let privateKey = P521.Signing.PrivateKey()
            return .ecdsa(
                .nistp521(rawRepresentation: Array(privateKey.rawRepresentation))
            )
        case let .rsa(bitCount):
            return .rsa(try SSHRSAPrivateKey.generate(bitCount: bitCount))
        }
    }

    var algorithm: SSHOpenSSHKeyPair.Algorithm {
        switch self {
        case .ed25519:
            return .ed25519
        case let .ecdsa(privateKey):
            switch privateKey.curve {
            case .nistp256:
                return .ecdsaP256
            case .nistp384:
                return .ecdsaP384
            case .nistp521:
                return .ecdsaP521
            }
        case let .rsa(privateKey):
            let components = try? SSHRSAPKCS1DERCodec.parsePrivateKey(
                privateKey.pkcs1DERRepresentation
            )
            let bitCount = components.map { Self.bitCount(of: $0.modulus) } ?? 0
            return .rsa(bitCount: bitCount)
        }
    }

    var authenticationMethod: SSHAuthenticationMethod {
        switch self {
        case let .ed25519(privateKey):
            return .ed25519PrivateKey(rawRepresentation: privateKey.rawRepresentation)
        case let .ecdsa(privateKey):
            switch privateKey {
            case let .nistp256(rawRepresentation):
                return .ecdsaP256PrivateKey(rawRepresentation: rawRepresentation)
            case let .nistp384(rawRepresentation):
                return .ecdsaP384PrivateKey(rawRepresentation: rawRepresentation)
            case let .nistp521(rawRepresentation):
                return .ecdsaP521PrivateKey(rawRepresentation: rawRepresentation)
            }
        case let .rsa(privateKey):
            return .rsaPrivateKey(pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation)
        }
    }

    func authorizedKeyLine(comment: String) throws -> String {
        switch self {
        case let .ed25519(privateKey):
            return try privateKey.authorizedKeyLine(comment: comment)
        case let .ecdsa(privateKey):
            return try privateKey.authorizedKeyLine(comment: comment)
        case let .rsa(privateKey):
            return try privateKey.authorizedKeyLine(comment: comment)
        }
    }

    func publicKeyBlob() throws -> [UInt8] {
        switch self {
        case let .ed25519(privateKey):
            let cryptoPrivateKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: Data(privateKey.rawRepresentation)
            )
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(cryptoPrivateKey.publicKey.rawRepresentation))
            return writer.bytes
        case let .ecdsa(privateKey):
            var writer = SSHWireWriter()
            writer.write(utf8: privateKey.curve.algorithmName)
            writer.write(utf8: privateKey.curve.rawValue)
            writer.write(string: try privateKey.publicKeyBytes())
            return writer.bytes
        case let .rsa(privateKey):
            return privateKey.publicKeyBlob
        }
    }

    func writePrivateKeyBody(into writer: inout SSHWireWriter) throws {
        switch self {
        case let .ed25519(privateKey):
            let cryptoPrivateKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: Data(privateKey.rawRepresentation)
            )
            let publicKey = Array(cryptoPrivateKey.publicKey.rawRepresentation)
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: publicKey)
            writer.write(string: privateKey.rawRepresentation + publicKey)
        case let .ecdsa(privateKey):
            writer.write(utf8: privateKey.curve.algorithmName)
            writer.write(utf8: privateKey.curve.rawValue)
            writer.write(string: try privateKey.publicKeyBytes())
            writer.write(mpint: SSHMPInt(unsignedMagnitude: privateKey.rawRepresentation))
        case let .rsa(privateKey):
            let components = try SSHRSAPKCS1DERCodec.parsePrivateKey(
                privateKey.pkcs1DERRepresentation
            )
            writer.write(utf8: "ssh-rsa")
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.modulus))
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.publicExponent))
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.privateExponent))
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.coefficient))
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.prime1))
            writer.write(mpint: SSHMPInt(unsignedMagnitude: components.prime2))
        }
    }

    private static func bitCount(of bytes: [UInt8]) -> Int {
        guard let firstNonZeroIndex = bytes.firstIndex(where: { $0 != 0 }) else {
            return 0
        }

        let significantBytes = bytes[firstNonZeroIndex...]
        let leadingZeroBits = significantBytes.first?.leadingZeroBitCount ?? 0
        return significantBytes.count * 8 - leadingZeroBits
    }
}
private enum SSHOpenSSHPrivateKeySerializer {
    private static let magic = Array("openssh-key-v1".utf8) + [0]
    private static let bcryptSaltByteCount = 16
    private static let pemLineLength = 70

    static func serialize(
        privateKey: SSHOpenSSHGeneratedPrivateKey,
        comment: String,
        encryption: SSHOpenSSHPrivateKeyEncryption?
    ) throws -> String {
        let cipher = encryption?.cipher.privateKeyCipher ?? .none
        let kdf = try self.makeKDF(encryption: encryption)

        var privateKeyBlockWriter = SSHWireWriter()
        let checkint = try self.randomUInt32()
        privateKeyBlockWriter.write(uint32: checkint)
        privateKeyBlockWriter.write(uint32: checkint)
        try privateKey.writePrivateKeyBody(into: &privateKeyBlockWriter)
        privateKeyBlockWriter.write(utf8: comment)
        privateKeyBlockWriter.write(
            rawBytes: self.padding(
                currentLength: privateKeyBlockWriter.bytes.count,
                blockSize: cipher.blockSize
            )
        )

        let keyMaterial = try kdf.deriveKeyMaterial(
            passphrase: encryption?.passphrase,
            byteCount: cipher.keyByteCount + cipher.ivByteCount
        )
        let encryptedPrivateKeyBlock = try cipher.encrypt(
            privateKeyBlock: privateKeyBlockWriter.bytes,
            using: keyMaterial
        )

        var writer = SSHWireWriter()
        writer.write(rawBytes: Self.magic)
        writer.write(utf8: cipher.name)
        writer.write(utf8: kdf.name)
        writer.write(string: kdf.encodedOptions)
        writer.write(uint32: 1)
        writer.write(string: try privateKey.publicKeyBlob())
        writer.write(string: encryptedPrivateKeyBlock)

        return self.makePEM(encodedPayload: writer.bytes)
    }

    private static func makeKDF(
        encryption: SSHOpenSSHPrivateKeyEncryption?
    ) throws -> SSHOpenSSHPrivateKeyKDF {
        guard let encryption else {
            return .none
        }

        guard !encryption.passphrase.isEmpty else {
            throw SSHAuthenticationMethodError.missingOpenSSHPrivateKeyPassphrase
        }

        return .bcrypt(
            SSHOpenSSHPrivateKeyKDFOptions(
                salt: try self.randomBytes(count: Self.bcryptSaltByteCount),
                rounds: encryption.rounds
            )
        )
    }

    private static func padding(currentLength: Int, blockSize: Int) -> [UInt8] {
        guard blockSize > 0 else {
            return []
        }

        let remainder = currentLength % blockSize
        guard remainder != 0 else {
            return []
        }

        let paddingLength = blockSize - remainder
        return (1...paddingLength).map {
            UInt8($0 & 0xff)
        }
    }

    private static func makePEM(encodedPayload: [UInt8]) -> String {
        let base64 = Data(encodedPayload).base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: Self.pemLineLength).map {
            startIndex -> String in
            let start = base64.index(base64.startIndex, offsetBy: startIndex)
            let end = base64.index(
                start,
                offsetBy: min(Self.pemLineLength, base64.count - startIndex)
            )
            return String(base64[start..<end])
        }

        return """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(lines.joined(separator: "\n"))
        -----END OPENSSH PRIVATE KEY-----

        """
    }

    private static func randomUInt32() throws -> UInt32 {
        let bytes = try self.randomBytes(count: 4)
        return (UInt32(bytes[0]) << 24)
            | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
    }

    private static func randomBytes(count: Int) throws -> [UInt8] {
        guard count >= 0 else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        var bytes = Array(repeating: UInt8.zero, count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return bytes
    }
}
private extension SSHOpenSSHPrivateKeyEncryption.Cipher {
    var privateKeyCipher: SSHOpenSSHPrivateKeyCipher {
        switch self {
        case .aes128CTR:
            return .aes128CTR
        case .aes192CTR:
            return .aes192CTR
        case .aes256CTR:
            return .aes256CTR
        case .aes128CBC:
            return .aes128CBC
        case .aes192CBC:
            return .aes192CBC
        case .aes256CBC:
            return .aes256CBC
        }
    }
}
