// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

package enum SSHEllipticCurveKeyExchangeError: Error, Equatable, Sendable {
    case unsupportedKeyExchangeAlgorithm(String)
    case invalidRemotePublicKeyLength(Int)
    case invalidRemotePublicKey
    case allZeroSharedSecret
}

package struct SSHEllipticCurveKeyPair: Equatable, Sendable {
    let privateKey: [UInt8]
    let publicKey: [UInt8]
}

package struct SSHEllipticCurveClientKeyExchangeResult: Equatable, Sendable {
    let keyExchangeAlgorithm: String
    let clientEphemeralPublicKey: [UInt8]
    let serverHostKey: [UInt8]
    let serverEphemeralPublicKey: [UInt8]
    let serverSignature: [UInt8]
    let sharedSecret: SSHMPInt
    let exchangeHash: [UInt8]
    let sessionIdentifier: [UInt8]
}
extension SSHEllipticCurveClientKeyExchangeResult {
    func verifyServerHostKey(
        expectedHostKeyAlgorithm: String,
        verifier: SSHHostKeyVerifier = SSHHostKeyVerifier()
    ) throws -> SSHVerifiedHostKey {
        try verifier.verifyHostKey(
            expectedHostKeyAlgorithm: expectedHostKeyAlgorithm,
            exchangeHash: self.exchangeHash,
            hostKey: self.serverHostKey,
            signature: self.serverSignature
        )
    }

    func deriveTransportKeyMaterial(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        keyDeriver: SSHTransportKeyDeriver = SSHTransportKeyDeriver()
    ) throws -> SSHTransportKeyMaterial {
        try self.deriveTransportKeyMaterial(
            negotiatedAlgorithms: negotiatedAlgorithms,
            sessionIdentifier: self.sessionIdentifier,
            keyDeriver: keyDeriver
        )
    }

    func deriveTransportKeyMaterial(
        negotiatedAlgorithms: SSHNegotiatedAlgorithms,
        sessionIdentifier: [UInt8],
        keyDeriver: SSHTransportKeyDeriver = SSHTransportKeyDeriver()
    ) throws -> SSHTransportKeyMaterial {
        try keyDeriver.deriveKeys(
            negotiatedAlgorithms: negotiatedAlgorithms,
            sharedSecret: self.sharedSecret,
            exchangeHash: self.exchangeHash,
            sessionIdentifier: sessionIdentifier
        )
    }
}
package struct SSHEllipticCurveKeyExchange: Sendable {
    private static let supportedAlgorithms: Set<String> = [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ]

    func generateKeyPair(
        keyExchangeAlgorithm: String = "curve25519-sha256"
    ) throws -> SSHEllipticCurveKeyPair {
        guard Self.supportedAlgorithms.contains(keyExchangeAlgorithm) else {
            throw SSHEllipticCurveKeyExchangeError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }

        switch keyExchangeAlgorithm {
        case "curve25519-sha256", "curve25519-sha256@libssh.org":
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            return SSHEllipticCurveKeyPair(
                privateKey: Array(privateKey.rawRepresentation),
                publicKey: Array(privateKey.publicKey.rawRepresentation)
            )
        case "ecdh-sha2-nistp256":
            let privateKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            return SSHEllipticCurveKeyPair(
                privateKey: Array(privateKey.rawRepresentation),
                publicKey: Array(privateKey.publicKey.x963Representation)
            )
        case "ecdh-sha2-nistp384":
            let privateKey = P384.KeyAgreement.PrivateKey(compactRepresentable: false)
            return SSHEllipticCurveKeyPair(
                privateKey: Array(privateKey.rawRepresentation),
                publicKey: Array(privateKey.publicKey.x963Representation)
            )
        case "ecdh-sha2-nistp521":
            let privateKey = P521.KeyAgreement.PrivateKey(compactRepresentable: false)
            return SSHEllipticCurveKeyPair(
                privateKey: Array(privateKey.rawRepresentation),
                publicKey: Array(privateKey.publicKey.x963Representation)
            )
        default:
            throw SSHEllipticCurveKeyExchangeError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }
    }

    func completeClientKeyExchange(
        keyExchangeAlgorithm: String,
        clientIdentification: SSHIdentification,
        serverIdentification: SSHIdentification,
        clientKeyExchangeInitPayload: [UInt8],
        serverKeyExchangeInitPayload: [UInt8],
        clientKeyPair: SSHEllipticCurveKeyPair,
        serverHostKey: [UInt8],
        serverEphemeralPublicKey: [UInt8],
        serverSignature: [UInt8]
    ) throws -> SSHEllipticCurveClientKeyExchangeResult {
        guard Self.supportedAlgorithms.contains(keyExchangeAlgorithm) else {
            throw SSHEllipticCurveKeyExchangeError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }

        let sharedSecretBytes: [UInt8]
        switch keyExchangeAlgorithm {
        case "curve25519-sha256", "curve25519-sha256@libssh.org":
            guard serverEphemeralPublicKey.count == 32 else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKeyLength(
                    serverEphemeralPublicKey.count
                )
            }

            guard
                let privateKey = try? Curve25519.KeyAgreement.PrivateKey(
                    rawRepresentation: Data(clientKeyPair.privateKey)
                ),
                let serverPublicKey = try? Curve25519.KeyAgreement.PublicKey(
                    rawRepresentation: Data(serverEphemeralPublicKey)
                )
            else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKey
            }

            sharedSecretBytes = try privateKey.sharedSecretFromKeyAgreement(
                with: serverPublicKey
            ).withUnsafeBytes { Array($0) }

            guard !sharedSecretBytes.allSatisfy({ $0 == 0 }) else {
                throw SSHEllipticCurveKeyExchangeError.allZeroSharedSecret
            }
        case "ecdh-sha2-nistp256":
            guard serverEphemeralPublicKey.count == 65 else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKeyLength(
                    serverEphemeralPublicKey.count
                )
            }

            guard
                let privateKey = try? P256.KeyAgreement.PrivateKey(
                    rawRepresentation: Data(clientKeyPair.privateKey)
                ),
                let serverPublicKey = try? P256.KeyAgreement.PublicKey(
                    x963Representation: Data(serverEphemeralPublicKey)
                )
            else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKey
            }

            sharedSecretBytes = try privateKey.sharedSecretFromKeyAgreement(
                with: serverPublicKey
            ).withUnsafeBytes { Array($0) }
        case "ecdh-sha2-nistp384":
            guard serverEphemeralPublicKey.count == 97 else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKeyLength(
                    serverEphemeralPublicKey.count
                )
            }

            guard
                let privateKey = try? P384.KeyAgreement.PrivateKey(
                    rawRepresentation: Data(clientKeyPair.privateKey)
                ),
                let serverPublicKey = try? P384.KeyAgreement.PublicKey(
                    x963Representation: Data(serverEphemeralPublicKey)
                )
            else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKey
            }

            sharedSecretBytes = try privateKey.sharedSecretFromKeyAgreement(
                with: serverPublicKey
            ).withUnsafeBytes { Array($0) }
        case "ecdh-sha2-nistp521":
            guard serverEphemeralPublicKey.count == 133 else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKeyLength(
                    serverEphemeralPublicKey.count
                )
            }

            guard
                let privateKey = try? P521.KeyAgreement.PrivateKey(
                    rawRepresentation: Data(clientKeyPair.privateKey)
                ),
                let serverPublicKey = try? P521.KeyAgreement.PublicKey(
                    x963Representation: Data(serverEphemeralPublicKey)
                )
            else {
                throw SSHEllipticCurveKeyExchangeError.invalidRemotePublicKey
            }

            sharedSecretBytes = try privateKey.sharedSecretFromKeyAgreement(
                with: serverPublicKey
            ).withUnsafeBytes { Array($0) }
        default:
            throw SSHEllipticCurveKeyExchangeError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }

        let sharedSecret = SSHMPInt(unsignedMagnitude: sharedSecretBytes)
        let exchangeHash = try self.exchangeHash(
            keyExchangeAlgorithm: keyExchangeAlgorithm,
            clientIdentification: clientIdentification,
            serverIdentification: serverIdentification,
            clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
            serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
            serverHostKey: serverHostKey,
            clientEphemeralPublicKey: clientKeyPair.publicKey,
            serverEphemeralPublicKey: serverEphemeralPublicKey,
            sharedSecret: sharedSecret
        )

        return SSHEllipticCurveClientKeyExchangeResult(
            keyExchangeAlgorithm: keyExchangeAlgorithm,
            clientEphemeralPublicKey: clientKeyPair.publicKey,
            serverHostKey: serverHostKey,
            serverEphemeralPublicKey: serverEphemeralPublicKey,
            serverSignature: serverSignature,
            sharedSecret: sharedSecret,
            exchangeHash: exchangeHash,
            sessionIdentifier: exchangeHash
        )
    }

    private func exchangeHash(
        keyExchangeAlgorithm: String,
        clientIdentification: SSHIdentification,
        serverIdentification: SSHIdentification,
        clientKeyExchangeInitPayload: [UInt8],
        serverKeyExchangeInitPayload: [UInt8],
        serverHostKey: [UInt8],
        clientEphemeralPublicKey: [UInt8],
        serverEphemeralPublicKey: [UInt8],
        sharedSecret: SSHMPInt
    ) throws -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: clientIdentification.rawValue)
        writer.write(utf8: serverIdentification.rawValue)
        writer.write(string: clientKeyExchangeInitPayload)
        writer.write(string: serverKeyExchangeInitPayload)
        writer.write(string: serverHostKey)
        writer.write(string: clientEphemeralPublicKey)
        writer.write(string: serverEphemeralPublicKey)
        writer.write(mpint: sharedSecret)

        switch keyExchangeAlgorithm {
        case "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256":
            return Array(SHA256.hash(data: writer.bytes))
        case "ecdh-sha2-nistp384":
            return Array(SHA384.hash(data: writer.bytes))
        case "ecdh-sha2-nistp521":
            return Array(SHA512.hash(data: writer.bytes))
        default:
            throw SSHEllipticCurveKeyExchangeError.unsupportedKeyExchangeAlgorithm(
                keyExchangeAlgorithm
            )
        }
    }
}

package typealias SSHCurve25519KeyExchangeError = SSHEllipticCurveKeyExchangeError
package typealias SSHCurve25519KeyPair = SSHEllipticCurveKeyPair
package typealias SSHCurve25519ClientKeyExchangeResult = SSHEllipticCurveClientKeyExchangeResult
package typealias SSHCurve25519KeyExchange = SSHEllipticCurveKeyExchange
