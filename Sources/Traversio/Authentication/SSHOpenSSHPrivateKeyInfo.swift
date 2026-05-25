// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

/// Errors raised while reading metadata from an OpenSSH private-key envelope.
public enum SSHOpenSSHPrivateKeyInfoError: Error, Equatable, Sendable {
    /// The text does not use the OpenSSH private-key PEM markers.
    case invalidPEM
    /// The PEM body is empty or is not valid Base64.
    case invalidBase64
    /// The decoded payload does not start with the OpenSSH private-key magic.
    case invalidMagic
    /// The decoded payload is not a complete OpenSSH private-key envelope.
    case invalidEnvelope
    /// The envelope does not contain a usable public-key list.
    case invalidKeyCount(UInt32)
    /// The KDF options string is malformed for the named KDF.
    case invalidKDFOptions(String)
    /// One public-key blob in the envelope is malformed.
    case invalidPublicKey(index: Int)
}

/// ECDSA curve names used by OpenSSH private-key metadata.
public enum SSHOpenSSHECDSACurve: String, Equatable, Sendable {
    /// NIST P-256, encoded by OpenSSH as `nistp256`.
    case nistp256
    /// NIST P-384, encoded by OpenSSH as `nistp384`.
    case nistp384
    /// NIST P-521, encoded by OpenSSH as `nistp521`.
    case nistp521

    init?(algorithmName: String) {
        switch algorithmName {
        case "ecdsa-sha2-nistp256":
            self = .nistp256
        case "ecdsa-sha2-nistp384":
            self = .nistp384
        case "ecdsa-sha2-nistp521":
            self = .nistp521
        default:
            return nil
        }
    }

    /// SSH public-key algorithm name for this curve.
    public var algorithmName: String {
        "ecdsa-sha2-\(self.rawValue)"
    }
}

/// Public-key algorithm metadata read from an OpenSSH private-key envelope.
public enum SSHOpenSSHPrivateKeyAlgorithm: Equatable, Sendable {
    /// Ed25519 public-key authentication key.
    case ed25519
    /// RSA public-key authentication key with the public modulus bit count.
    case rsa(modulusBitCount: Int)
    /// ECDSA public-key authentication key with the named OpenSSH curve.
    case ecdsa(curve: SSHOpenSSHECDSACurve)
    /// OpenSSH certificate key metadata.
    case certificate(algorithmName: String, baseAlgorithmName: String)
    /// A syntactically readable algorithm Traversio does not classify yet.
    case unknown(String)

    /// SSH public-key algorithm name from the envelope.
    public var algorithmName: String {
        switch self {
        case .ed25519:
            return "ssh-ed25519"
        case .rsa:
            return "ssh-rsa"
        case let .ecdsa(curve):
            return curve.algorithmName
        case let .certificate(algorithmName, _):
            return algorithmName
        case let .unknown(algorithmName):
            return algorithmName
        }
    }
}

/// Metadata from an OpenSSH `openssh-key-v1` private-key envelope.
///
/// This type reads the unencrypted envelope header and public-key blobs. It
/// does not decrypt the private-key block and does not prove that the private
/// key can authenticate.
public struct SSHOpenSSHPrivateKeyInfo: Equatable, Sendable {
    /// OpenSSH private-key cipher metadata.
    public enum Cipher: Equatable, Sendable {
        /// Unencrypted private-key block.
        case none
        /// AES-128 CTR encryption.
        case aes128CTR
        /// AES-192 CTR encryption.
        case aes192CTR
        /// AES-256 CTR encryption.
        case aes256CTR
        /// AES-128 CBC encryption.
        case aes128CBC
        /// AES-192 CBC encryption.
        case aes192CBC
        /// AES-256 CBC encryption.
        case aes256CBC
        /// Cipher name not classified by this Traversio release.
        case unknown(String)

        init(name: String) {
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
                self = .unknown(name)
            }
        }

        /// OpenSSH cipher name.
        public var name: String {
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
            case let .unknown(name):
                return name
            }
        }

        /// Whether this cipher name represents an encrypted private-key block.
        public var isEncrypted: Bool {
            self.name != "none"
        }
    }

    /// OpenSSH private-key KDF metadata.
    public enum KeyDerivationFunction: Equatable, Sendable {
        /// No KDF is used.
        case none
        /// OpenSSH bcrypt KDF options.
        case bcrypt(salt: [UInt8], rounds: UInt32)
        /// KDF name not classified by this Traversio release.
        case unknown(name: String, options: [UInt8])

        init(name: String, options: [UInt8]) throws {
            switch name {
            case "none":
                guard options.isEmpty else {
                    throw SSHOpenSSHPrivateKeyInfoError.invalidKDFOptions(name)
                }
                self = .none
            case "bcrypt":
                do {
                    var reader = SSHWireReader(bytes: options)
                    let salt = try reader.readString()
                    let rounds = try reader.readUInt32()
                    guard salt.isEmpty == false, reader.isAtEnd else {
                        throw SSHOpenSSHPrivateKeyInfoError.invalidKDFOptions(name)
                    }
                    self = .bcrypt(salt: salt, rounds: rounds)
                } catch let error as SSHOpenSSHPrivateKeyInfoError {
                    throw error
                } catch {
                    throw SSHOpenSSHPrivateKeyInfoError.invalidKDFOptions(name)
                }
            default:
                self = .unknown(name: name, options: options)
            }
        }

        /// OpenSSH KDF name.
        public var name: String {
            switch self {
            case .none:
                return "none"
            case .bcrypt:
                return "bcrypt"
            case let .unknown(name, _):
                return name
            }
        }

        /// Raw OpenSSH KDF options.
        public var options: [UInt8] {
            switch self {
            case .none:
                return []
            case let .bcrypt(salt, rounds):
                var writer = SSHWireWriter()
                writer.write(string: salt)
                writer.write(uint32: rounds)
                return writer.bytes
            case let .unknown(_, options):
                return options
            }
        }
    }

    /// One public key listed in an OpenSSH private-key envelope.
    public struct PublicKey: Equatable, Sendable {
        /// Zero-based position in the envelope public-key list.
        public let index: Int
        /// SSH algorithm name read from the public-key blob.
        public let algorithmName: String
        /// Classified algorithm metadata.
        public let algorithm: SSHOpenSSHPrivateKeyAlgorithm
        /// Raw SSH public-key blob from the envelope.
        public let publicKeyBlob: [UInt8]

        /// SHA-256 fingerprint of the raw SSH public-key blob, encoded as hex.
        public var fingerprintSHA256: String {
            let digest = SHA256.hash(data: Data(self.publicKeyBlob))
            return digest.map { String(format: "%02x", $0) }.joined()
        }

        /// Returns an `authorized_keys`-style public-key line.
        public func authorizedKeyLine(comment: String = "") -> String {
            let prefix = "\(self.algorithmName) \(Data(self.publicKeyBlob).base64EncodedString())"
            guard comment.isEmpty == false else {
                return prefix
            }
            return "\(prefix) \(comment)"
        }
    }

    /// OpenSSH cipher name.
    public let cipherName: String
    /// Classified cipher metadata.
    public let cipher: Cipher
    /// OpenSSH KDF name.
    public let kdfName: String
    /// Classified KDF metadata.
    public let keyDerivationFunction: KeyDerivationFunction
    /// Number of public keys listed by the envelope.
    public let keyCount: UInt32
    /// Public-key metadata listed by the envelope.
    public let publicKeys: [PublicKey]
    /// Byte length of the encrypted or plaintext private-key block.
    public let privateKeyBlockByteCount: Int

    /// First public key in the envelope.
    public var primaryPublicKey: PublicKey {
        self.publicKeys[0]
    }

    /// Whether the private-key block is encrypted.
    public var isEncrypted: Bool {
        self.cipher.isEncrypted
    }

    /// Parses metadata from an OpenSSH private-key PEM string.
    public static func parse(_ pem: String) throws -> SSHOpenSSHPrivateKeyInfo {
        let encodedPayload = try SSHOpenSSHPrivateKeyEnvelopeParser.decodePEM(pem)
        let envelope = try SSHOpenSSHPrivateKeyEnvelopeParser.parseEnvelope(encodedPayload)
        return try SSHOpenSSHPrivateKeyInfo(envelope: envelope)
    }

    /// Loads and parses metadata from an OpenSSH private-key PEM file.
    public static func parse(contentsOfFile path: String) throws -> SSHOpenSSHPrivateKeyInfo {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        return try self.parse(pem)
    }

    init(envelope: SSHOpenSSHPrivateKeyEnvelope) throws {
        let cipher = Cipher(name: envelope.cipherName)
        let keyDerivationFunction = try KeyDerivationFunction(
            name: envelope.kdfName,
            options: envelope.kdfOptions
        )
        guard cipher.isEncrypted == (keyDerivationFunction.name != "none") else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
        }

        self.cipherName = envelope.cipherName
        self.cipher = cipher
        self.kdfName = envelope.kdfName
        self.keyDerivationFunction = keyDerivationFunction
        self.keyCount = envelope.keyCount
        self.publicKeys = try envelope.publicKeyBlobs.enumerated().map {
            try Self.parsePublicKey(index: $0.offset, publicKeyBlob: $0.element)
        }
        self.privateKeyBlockByteCount = envelope.privateKeyBlock.count
    }

    private static func parsePublicKey(
        index: Int,
        publicKeyBlob: [UInt8]
    ) throws -> PublicKey {
        do {
            var reader = SSHWireReader(bytes: publicKeyBlob)
            let algorithmName = try reader.readUTF8String()
            let algorithm = try self.parseAlgorithm(
                algorithmName: algorithmName,
                reader: &reader
            )
            return PublicKey(
                index: index,
                algorithmName: algorithmName,
                algorithm: algorithm,
                publicKeyBlob: publicKeyBlob
            )
        } catch {
            throw SSHOpenSSHPrivateKeyInfoError.invalidPublicKey(index: index)
        }
    }

    private static func parseAlgorithm(
        algorithmName: String,
        reader: inout SSHWireReader
    ) throws -> SSHOpenSSHPrivateKeyAlgorithm {
        switch algorithmName {
        case "ssh-ed25519":
            let publicKey = try reader.readString()
            guard publicKey.count == 32, reader.isAtEnd else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
            }
            return .ed25519
        case "ssh-rsa":
            let publicExponent = try self.decodePositiveMPInt(reader.readMPInt())
            let modulus = try self.decodePositiveMPInt(reader.readMPInt())
            guard publicExponent.isEmpty == false,
                  modulus.isEmpty == false,
                  reader.isAtEnd else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
            }
            return .rsa(modulusBitCount: self.bitCount(of: modulus))
        case let name where name.hasSuffix("-cert-v01@openssh.com"):
            let suffix = "-cert-v01@openssh.com"
            let baseName = String(name.dropLast(suffix.count))
            return .certificate(algorithmName: name, baseAlgorithmName: baseName)
        case let name:
            if let curve = SSHOpenSSHECDSACurve(algorithmName: name) {
                let curveName = try reader.readUTF8String()
                let publicKey = try reader.readString()
                guard curveName == curve.rawValue, reader.isAtEnd else {
                    throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
                }
                try self.validateECDSAPublicKey(publicKey, curve: curve)
                return .ecdsa(curve: curve)
            }
            return .unknown(name)
        }
    }

    private static func validateECDSAPublicKey(
        _ publicKey: [UInt8],
        curve: SSHOpenSSHECDSACurve
    ) throws {
        switch curve {
        case .nistp256:
            _ = try P256.Signing.PublicKey(x963Representation: Data(publicKey))
        case .nistp384:
            _ = try P384.Signing.PublicKey(x963Representation: Data(publicKey))
        case .nistp521:
            _ = try P521.Signing.PublicKey(x963Representation: Data(publicKey))
        }
    }

    private static func decodePositiveMPInt(_ value: SSHMPInt) throws -> [UInt8] {
        let encodedBytes = value.encodedBytes
        guard encodedBytes.first.map({ $0 & 0x80 == 0 }) ?? true else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
        }
        let magnitude = encodedBytes.first == 0
            ? Array(encodedBytes.dropFirst())
            : encodedBytes
        guard magnitude.isEmpty == false else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
        }
        return magnitude
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

struct SSHOpenSSHPrivateKeyEnvelope {
    let cipherName: String
    let kdfName: String
    let kdfOptions: [UInt8]
    let keyCount: UInt32
    let publicKeyBlobs: [[UInt8]]
    let privateKeyBlock: [UInt8]
}

enum SSHOpenSSHPrivateKeyEnvelopeParser {
    static let pemBeginMarker = "-----BEGIN OPENSSH PRIVATE KEY-----"
    static let pemEndMarker = "-----END OPENSSH PRIVATE KEY-----"
    static let magic = Array("openssh-key-v1".utf8) + [0]

    static func decodePEM(_ pem: String) throws -> [UInt8] {
        let lines = pem
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.isEmpty == false }

        guard lines.count >= 3,
              lines.first == Self.pemBeginMarker,
              lines.last == Self.pemEndMarker else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidPEM
        }

        let body = lines.dropFirst().dropLast().joined()
        guard body.isEmpty == false else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidBase64
        }
        guard let decoded = Data(base64Encoded: body) else {
            throw SSHOpenSSHPrivateKeyInfoError.invalidBase64
        }
        return Array(decoded)
    }

    static func parseEnvelope(_ encodedPayload: [UInt8]) throws -> SSHOpenSSHPrivateKeyEnvelope {
        do {
            var reader = SSHWireReader(bytes: encodedPayload)
            let magic = try reader.readRawBytes(count: Self.magic.count)
            guard magic == Self.magic else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidMagic
            }

            let cipherName = try reader.readUTF8String()
            let kdfName = try reader.readUTF8String()
            let kdfOptions = try reader.readString()
            let keyCount = try reader.readUInt32()
            guard keyCount > 0 else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidKeyCount(keyCount)
            }
            guard UInt64(keyCount) <= UInt64(reader.remainingByteCount / 4) else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidKeyCount(keyCount)
            }

            var publicKeyBlobs: [[UInt8]] = []
            publicKeyBlobs.reserveCapacity(Int(keyCount))
            for _ in 0..<keyCount {
                publicKeyBlobs.append(try reader.readString())
            }

            let privateKeyBlock = try reader.readString()
            guard reader.isAtEnd else {
                throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
            }

            return SSHOpenSSHPrivateKeyEnvelope(
                cipherName: cipherName,
                kdfName: kdfName,
                kdfOptions: kdfOptions,
                keyCount: keyCount,
                publicKeyBlobs: publicKeyBlobs,
                privateKeyBlock: privateKeyBlock
            )
        } catch let error as SSHOpenSSHPrivateKeyInfoError {
            throw error
        } catch {
            throw SSHOpenSSHPrivateKeyInfoError.invalidEnvelope
        }
    }
}
