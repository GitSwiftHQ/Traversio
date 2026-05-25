// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

package enum SSHECDSAPrivateKeyError: Error, Equatable, Sendable {
    case invalidP256PrivateKey
    case invalidP384PrivateKey
    case invalidP521PrivateKey
}

enum SSHECDSACurve: String, Equatable, Sendable {
    case nistp256
    case nistp384
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

    var algorithmName: String {
        "ecdsa-sha2-\(self.rawValue)"
    }

    var coordinateByteCount: Int {
        switch self {
        case .nistp256:
            return 32
        case .nistp384:
            return 48
        case .nistp521:
            return 66
        }
    }
}
package enum SSHECDSAPrivateKey: Equatable, Sendable {
    case nistp256(rawRepresentation: [UInt8])
    case nistp384(rawRepresentation: [UInt8])
    case nistp521(rawRepresentation: [UInt8])

    init(curve: SSHECDSACurve, rawRepresentation: [UInt8]) {
        switch curve {
        case .nistp256:
            self = .nistp256(rawRepresentation: rawRepresentation)
        case .nistp384:
            self = .nistp384(rawRepresentation: rawRepresentation)
        case .nistp521:
            self = .nistp521(rawRepresentation: rawRepresentation)
        }
    }

    var curve: SSHECDSACurve {
        switch self {
        case .nistp256:
            return .nistp256
        case .nistp384:
            return .nistp384
        case .nistp521:
            return .nistp521
        }
    }

    var rawRepresentation: [UInt8] {
        switch self {
        case let .nistp256(rawRepresentation),
             let .nistp384(rawRepresentation),
             let .nistp521(rawRepresentation):
            return rawRepresentation
        }
    }

    package func authorizedKeyLine(comment: String = "traversio-probe") throws -> String {
        let request = try self.makeRequest(algorithmName: self.curve.algorithmName)
        return "\(self.curve.algorithmName) \(Data(request.publicKey).base64EncodedString()) \(comment)"
    }

    func validatePublicKeyMatches(_ expectedPublicKey: [UInt8]) throws {
        guard try self.publicKeyBytes() == expectedPublicKey else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }
    }

    func publicKeyBytes() throws -> [UInt8] {
        switch self {
        case let .nistp256(rawRepresentation):
            return try Array(self.p256PrivateKey(rawRepresentation).publicKey.x963Representation)
        case let .nistp384(rawRepresentation):
            return try Array(self.p384PrivateKey(rawRepresentation).publicKey.x963Representation)
        case let .nistp521(rawRepresentation):
            return try Array(self.p521PrivateKey(rawRepresentation).publicKey.x963Representation)
        }
    }

    private func signaturePayload(for bytes: [UInt8]) throws -> [UInt8] {
        switch self {
        case let .nistp256(rawRepresentation):
            let signature = try self.p256PrivateKey(rawRepresentation).signature(for: Data(bytes))
            return try Self.makeECDSASignaturePayload(
                rawSignature: Array(signature.rawRepresentation),
                coordinateByteCount: self.curve.coordinateByteCount
            )
        case let .nistp384(rawRepresentation):
            let signature = try self.p384PrivateKey(rawRepresentation).signature(for: Data(bytes))
            return try Self.makeECDSASignaturePayload(
                rawSignature: Array(signature.rawRepresentation),
                coordinateByteCount: self.curve.coordinateByteCount
            )
        case let .nistp521(rawRepresentation):
            let signature = try self.p521PrivateKey(rawRepresentation).signature(for: Data(bytes))
            return try Self.makeECDSASignaturePayload(
                rawSignature: Array(signature.rawRepresentation),
                coordinateByteCount: self.curve.coordinateByteCount
            )
        }
    }

    private static func makeECDSASignaturePayload(
        rawSignature: [UInt8],
        coordinateByteCount: Int
    ) throws -> [UInt8] {
        let expectedSignatureLength = coordinateByteCount * 2
        guard rawSignature.count == expectedSignatureLength else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        let r = SSHMPInt(unsignedMagnitude: Array(rawSignature.prefix(coordinateByteCount)))
        let s = SSHMPInt(unsignedMagnitude: Array(rawSignature.suffix(coordinateByteCount)))

        var writer = SSHWireWriter()
        writer.write(mpint: r)
        writer.write(mpint: s)
        return writer.bytes
    }

    private func p256PrivateKey(_ rawRepresentation: [UInt8]) throws -> P256.Signing.PrivateKey {
        do {
            return try P256.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
        } catch {
            throw SSHECDSAPrivateKeyError.invalidP256PrivateKey
        }
    }

    private func p384PrivateKey(_ rawRepresentation: [UInt8]) throws -> P384.Signing.PrivateKey {
        do {
            return try P384.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
        } catch {
            throw SSHECDSAPrivateKeyError.invalidP384PrivateKey
        }
    }

    private func p521PrivateKey(_ rawRepresentation: [UInt8]) throws -> P521.Signing.PrivateKey {
        do {
            return try P521.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
        } catch {
            throw SSHECDSAPrivateKeyError.invalidP521PrivateKey
        }
    }
}
extension SSHECDSAPrivateKey: SSHPublicKeyAuthenticationPrivateKey {
    package var supportedAlgorithmNames: [String] {
        [self.curve.algorithmName]
    }

    package func makeRequest(
        algorithmName: String
    ) throws -> SSHPublicKeyAuthenticationRequest {
        _ = algorithmName
        var writer = SSHWireWriter()
        writer.write(utf8: self.curve.algorithmName)
        writer.write(utf8: self.curve.rawValue)
        writer.write(string: try self.publicKeyBytes())

        return SSHPublicKeyAuthenticationRequest(
            algorithmName: self.curve.algorithmName,
            publicKey: writer.bytes,
            signature: nil
        )
    }

    package func signUserAuthenticationRequest(
        _ bytes: [UInt8],
        algorithmName: String
    ) throws -> [UInt8] {
        _ = algorithmName
        var writer = SSHWireWriter()
        writer.write(utf8: self.curve.algorithmName)
        writer.write(string: try self.signaturePayload(for: bytes))
        return writer.bytes
    }
}
