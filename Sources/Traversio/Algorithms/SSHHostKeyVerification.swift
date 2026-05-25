// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Security

enum SSHHostKeyVerificationError: Error, Equatable, Sendable {
    case unsupportedHostKeyAlgorithm(String)
    case unsupportedSignatureAlgorithm(String)
    case unsupportedCertificateAuthorityAlgorithm(String)
    case hostKeyAlgorithmMismatch(expected: String, received: String)
    case signatureAlgorithmMismatch(expected: String, received: String)
    case invalidEd25519PublicKeyLength(Int)
    case invalidEd25519SignatureLength(Int)
    case invalidEd25519PublicKey
    case invalidECDSACurveName(expected: String, received: String)
    case invalidECDSAPublicKey
    case invalidECDSASignature
    case invalidRSAPublicKey
    case invalidHostCertificate
    case invalidHostCertificateType(UInt32)
    case invalidHostCertificateAuthorityKey
    case invalidHostCertificateSignature
    case invalidSignature
}
package struct SSHVerifiedHostKey: Equatable, Sendable {
    package let algorithmName: String
    package let publicKey: [UInt8]
    package let rawHostKey: [UInt8]
    package let rawSignature: [UInt8]
    package let certificate: SSHVerifiedHostCertificate?
}
package struct SSHVerifiedHostCertificate: Equatable, Sendable {
    package let validPrincipals: [String]
    package let validAfter: UInt64
    package let validBefore: UInt64
    package let certificateAuthorityKey: SSHTrustedHostKey
}
package struct SSHHostKeyVerifier: Sendable {
    private static let ed25519AlgorithmName = "ssh-ed25519"
    private static let ed25519CertificateAlgorithmName = "ssh-ed25519-cert-v01@openssh.com"
    private static let rsaHostKeyAlgorithmName = "ssh-rsa"
    private static let certificateAlgorithmSuffix = "-cert-v01@openssh.com"
    private static let hostCertificateType: UInt32 = 2

    func verifyHostKey(
        expectedHostKeyAlgorithm: String,
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        switch expectedHostKeyAlgorithm {
        case Self.ed25519AlgorithmName:
            return try self.verifyEd25519HostKey(
                exchangeHash: exchangeHash,
                hostKey: hostKey,
                signature: signature
            )
        case Self.ed25519CertificateAlgorithmName:
            return try self.verifyEd25519HostCertificate(
                exchangeHash: exchangeHash,
                hostKey: hostKey,
                signature: signature
            )
        case let algorithmName where Self.ecdsaCertificateCurve(
            algorithmName: algorithmName
        ) != nil:
            return try self.verifyECDSAHostCertificate(
                expectedHostKeyAlgorithm: algorithmName,
                exchangeHash: exchangeHash,
                hostKey: hostKey,
                signature: signature
            )
        case let algorithmName where algorithmName.hasPrefix("ecdsa-sha2-"):
            guard let curve = SSHECDSACurve(algorithmName: algorithmName) else {
                throw SSHHostKeyVerificationError.unsupportedHostKeyAlgorithm(
                    expectedHostKeyAlgorithm
                )
            }

            return try self.verifyECDSAHostKey(
                curve: curve,
                exchangeHash: exchangeHash,
                hostKey: hostKey,
                signature: signature
            )
        case SSHRSAHostKeySignatureAlgorithm.rsaSHA512.rawValue,
             SSHRSAHostKeySignatureAlgorithm.rsaSHA256.rawValue,
             Self.rsaHostKeyAlgorithmName:
            return try self.verifyRSAHostKey(
                expectedSignatureAlgorithm: expectedHostKeyAlgorithm,
                exchangeHash: exchangeHash,
                hostKey: hostKey,
                signature: signature
            )
        default:
            throw SSHHostKeyVerificationError.unsupportedHostKeyAlgorithm(
                expectedHostKeyAlgorithm
            )
        }
    }

    private func verifyEd25519HostKey(
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        let parsedHostKey = try self.parseEd25519HostKey(hostKey)
        let parsedSignature = try self.parseEd25519Signature(signature)

        guard parsedSignature.algorithmName == Self.ed25519AlgorithmName else {
            throw SSHHostKeyVerificationError.signatureAlgorithmMismatch(
                expected: Self.ed25519AlgorithmName,
                received: parsedSignature.algorithmName
            )
        }

        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: Data(parsedHostKey.publicKey)
            )
        } catch {
            throw SSHHostKeyVerificationError.invalidEd25519PublicKey
        }

        guard publicKey.isValidSignature(
            Data(parsedSignature.signatureBytes),
            for: Data(exchangeHash)
        ) else {
            throw SSHHostKeyVerificationError.invalidSignature
        }

        return SSHVerifiedHostKey(
            algorithmName: parsedHostKey.algorithmName,
            publicKey: parsedHostKey.publicKey,
            rawHostKey: hostKey,
            rawSignature: signature,
            certificate: nil
        )
    }

    private func verifyEd25519HostCertificate(
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        let parsedCertificate = try self.parseEd25519HostCertificate(hostKey)
        let trustedCertificateAuthorityKey = try self.verifyCertificateAuthoritySignature(
            signedBytes: parsedCertificate.signedBytes,
            signature: parsedCertificate.certificateSignature,
            certificateAuthorityKey: parsedCertificate.certificateAuthorityKey
        )
        try self.verifyEd25519Signature(
            signedBytes: exchangeHash,
            signature: signature,
            publicKeyBytes: parsedCertificate.publicKey,
            invalidKeyError: .invalidEd25519PublicKey,
            invalidSignatureError: .invalidSignature
        )

        return SSHVerifiedHostKey(
            algorithmName: parsedCertificate.algorithmName,
            publicKey: parsedCertificate.publicKey,
            rawHostKey: hostKey,
            rawSignature: signature,
            certificate: SSHVerifiedHostCertificate(
                validPrincipals: parsedCertificate.validPrincipals,
                validAfter: parsedCertificate.validAfter,
                validBefore: parsedCertificate.validBefore,
                certificateAuthorityKey: trustedCertificateAuthorityKey
            )
        )
    }

    private func verifyECDSAHostCertificate(
        expectedHostKeyAlgorithm: String,
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        let parsedCertificate = try self.parseECDSAHostCertificate(
            hostKey,
            expectedAlgorithmName: expectedHostKeyAlgorithm
        )
        let trustedCertificateAuthorityKey = try self.verifyCertificateAuthoritySignature(
            signedBytes: parsedCertificate.signedBytes,
            signature: parsedCertificate.certificateSignature,
            certificateAuthorityKey: parsedCertificate.certificateAuthorityKey
        )
        try self.verifyECDSASignature(
            signedBytes: exchangeHash,
            signature: signature,
            curve: parsedCertificate.curve,
            publicKeyBytes: parsedCertificate.publicKey,
            invalidKeyError: .invalidECDSAPublicKey,
            invalidSignatureError: .invalidSignature
        )

        return SSHVerifiedHostKey(
            algorithmName: parsedCertificate.algorithmName,
            publicKey: parsedCertificate.publicKey,
            rawHostKey: hostKey,
            rawSignature: signature,
            certificate: SSHVerifiedHostCertificate(
                validPrincipals: parsedCertificate.validPrincipals,
                validAfter: parsedCertificate.validAfter,
                validBefore: parsedCertificate.validBefore,
                certificateAuthorityKey: trustedCertificateAuthorityKey
            )
        )
    }

    private func verifyECDSAHostKey(
        curve: SSHECDSACurve,
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        let parsedHostKey = try self.parseECDSAHostKey(hostKey)
        guard parsedHostKey.algorithmName == curve.algorithmName else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: curve.algorithmName,
                received: parsedHostKey.algorithmName
            )
        }
        guard parsedHostKey.curveName == curve.rawValue else {
            throw SSHHostKeyVerificationError.invalidECDSACurveName(
                expected: curve.rawValue,
                received: parsedHostKey.curveName
            )
        }

        try self.verifyECDSASignature(
            signedBytes: exchangeHash,
            signature: signature,
            curve: curve,
            publicKeyBytes: parsedHostKey.publicKey,
            invalidKeyError: .invalidECDSAPublicKey,
            invalidSignatureError: .invalidSignature
        )

        return SSHVerifiedHostKey(
            algorithmName: parsedHostKey.algorithmName,
            publicKey: parsedHostKey.publicKey,
            rawHostKey: hostKey,
            rawSignature: signature,
            certificate: nil
        )
    }

    private func verifyRSAHostKey(
        expectedSignatureAlgorithm: String,
        exchangeHash: [UInt8],
        hostKey: [UInt8],
        signature: [UInt8]
    ) throws -> SSHVerifiedHostKey {
        guard let signatureAlgorithm = SSHRSAHostKeySignatureAlgorithm(
            rawValue: expectedSignatureAlgorithm
        ) else {
            throw SSHHostKeyVerificationError.unsupportedHostKeyAlgorithm(
                expectedSignatureAlgorithm
            )
        }

        let parsedHostKey = try self.parseRSAHostKey(hostKey)
        let parsedSignature = try self.parseRSASignature(signature)
        guard parsedSignature.algorithmName == expectedSignatureAlgorithm else {
            throw SSHHostKeyVerificationError.signatureAlgorithmMismatch(
                expected: expectedSignatureAlgorithm,
                received: parsedSignature.algorithmName
            )
        }

        let publicKeyDERRepresentation = SSHRSAPKCS1DERCodec.encodePublicKey(
            modulus: parsedHostKey.modulus,
            publicExponent: parsedHostKey.publicExponent
        )
        var error: Unmanaged<CFError>?
        let attributes = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ] as CFDictionary

        guard let publicKey = SecKeyCreateWithData(
            Data(publicKeyDERRepresentation) as CFData,
            attributes,
            &error
        ) else {
            throw SSHHostKeyVerificationError.invalidRSAPublicKey
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .verify, signatureAlgorithm.secKeyAlgorithm) else {
            throw SSHHostKeyVerificationError.invalidRSAPublicKey
        }

        let isValid = SecKeyVerifySignature(
            publicKey,
            signatureAlgorithm.secKeyAlgorithm,
            Data(exchangeHash) as CFData,
            Data(parsedSignature.signatureBytes) as CFData,
            &error
        )
        guard isValid else {
            throw SSHHostKeyVerificationError.invalidSignature
        }

        return SSHVerifiedHostKey(
            algorithmName: parsedHostKey.algorithmName,
            publicKey: publicKeyDERRepresentation,
            rawHostKey: hostKey,
            rawSignature: signature,
            certificate: nil
        )
    }

    private func verifyCertificateAuthoritySignature(
        signedBytes: [UInt8],
        signature: [UInt8],
        certificateAuthorityKey: [UInt8]
    ) throws -> SSHTrustedHostKey {
        let trustedCertificateAuthorityKey: SSHTrustedHostKey
        do {
            trustedCertificateAuthorityKey = try SSHTrustedHostKey(
                rawRepresentation: certificateAuthorityKey
            )
        } catch {
            throw SSHHostKeyVerificationError.invalidHostCertificateAuthorityKey
        }

        switch trustedCertificateAuthorityKey.algorithmName {
        case Self.ed25519AlgorithmName:
            let parsedCertificateAuthorityKey: SSHParsedEd25519HostKey
            do {
                parsedCertificateAuthorityKey = try self.parseEd25519HostKey(
                    certificateAuthorityKey
                )
            } catch {
                throw SSHHostKeyVerificationError.invalidHostCertificateAuthorityKey
            }

            do {
                try self.verifyEd25519Signature(
                    signedBytes: signedBytes,
                    signature: signature,
                    publicKeyBytes: parsedCertificateAuthorityKey.publicKey,
                    invalidKeyError: .invalidHostCertificateAuthorityKey,
                    invalidSignatureError: .invalidHostCertificateSignature
                )
            } catch let error as SSHHostKeyVerificationError {
                switch error {
                case .unsupportedSignatureAlgorithm:
                    throw SSHHostKeyVerificationError.invalidHostCertificateSignature
                default:
                    throw error
                }
            }
        case let algorithmName where SSHECDSACurve(algorithmName: algorithmName) != nil:
            let parsedCertificateAuthorityKey: SSHParsedECDSAHostKey
            do {
                parsedCertificateAuthorityKey = try self.parseECDSAHostKey(
                    certificateAuthorityKey
                )
            } catch let error as SSHHostKeyVerificationError {
                switch error {
                case .hostKeyAlgorithmMismatch:
                    throw SSHHostKeyVerificationError.unsupportedCertificateAuthorityAlgorithm(
                        trustedCertificateAuthorityKey.algorithmName
                    )
                default:
                    throw SSHHostKeyVerificationError.invalidHostCertificateAuthorityKey
                }
            } catch {
                throw SSHHostKeyVerificationError.invalidHostCertificateAuthorityKey
            }

            guard let curve = SSHECDSACurve(
                algorithmName: parsedCertificateAuthorityKey.algorithmName
            ),
            parsedCertificateAuthorityKey.curveName == curve.rawValue else {
                throw SSHHostKeyVerificationError.invalidHostCertificateAuthorityKey
            }

            do {
                try self.verifyECDSASignature(
                    signedBytes: signedBytes,
                    signature: signature,
                    curve: curve,
                    publicKeyBytes: parsedCertificateAuthorityKey.publicKey,
                    invalidKeyError: .invalidHostCertificateAuthorityKey,
                    invalidSignatureError: .invalidHostCertificateSignature,
                    mismatchedSignatureError: .invalidHostCertificateSignature
                )
            } catch let error as SSHHostKeyVerificationError {
                switch error {
                case .unsupportedSignatureAlgorithm:
                    throw SSHHostKeyVerificationError.invalidHostCertificateSignature
                default:
                    throw error
                }
            }
        default:
            throw SSHHostKeyVerificationError.unsupportedCertificateAuthorityAlgorithm(
                trustedCertificateAuthorityKey.algorithmName
            )
        }

        return trustedCertificateAuthorityKey
    }

    private func verifyEd25519Signature(
        signedBytes: [UInt8],
        signature: [UInt8],
        publicKeyBytes: [UInt8],
        invalidKeyError: SSHHostKeyVerificationError,
        invalidSignatureError: SSHHostKeyVerificationError
    ) throws {
        let parsedSignature = try self.parseEd25519Signature(signature)

        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: Data(publicKeyBytes)
            )
        } catch {
            throw invalidKeyError
        }

        guard publicKey.isValidSignature(
            Data(parsedSignature.signatureBytes),
            for: Data(signedBytes)
        ) else {
            throw invalidSignatureError
        }
    }

    private func verifyECDSASignature(
        signedBytes: [UInt8],
        signature: [UInt8],
        curve: SSHECDSACurve,
        publicKeyBytes: [UInt8],
        invalidKeyError: SSHHostKeyVerificationError,
        invalidSignatureError: SSHHostKeyVerificationError,
        mismatchedSignatureError: SSHHostKeyVerificationError? = nil
    ) throws {
        let parsedSignature = try self.parseECDSASignature(signature)
        guard parsedSignature.algorithmName == curve.algorithmName else {
            if let mismatchedSignatureError {
                throw mismatchedSignatureError
            }
            throw SSHHostKeyVerificationError.signatureAlgorithmMismatch(
                expected: curve.algorithmName,
                received: parsedSignature.algorithmName
            )
        }

        let normalizedSignature = try self.normalizedECDSASignature(
            r: parsedSignature.r,
            s: parsedSignature.s,
            coordinateByteCount: curve.coordinateByteCount
        )

        let isValid: Bool
        switch curve {
        case .nistp256:
            let publicKey: P256.Signing.PublicKey
            let ecdsaSignature: P256.Signing.ECDSASignature
            do {
                publicKey = try P256.Signing.PublicKey(
                    x963Representation: Data(publicKeyBytes)
                )
            } catch {
                throw invalidKeyError
            }
            do {
                ecdsaSignature = try P256.Signing.ECDSASignature(
                    rawRepresentation: Data(normalizedSignature)
                )
            } catch {
                throw invalidSignatureError
            }
            isValid = publicKey.isValidSignature(
                ecdsaSignature,
                for: Data(signedBytes)
            )
        case .nistp384:
            let publicKey: P384.Signing.PublicKey
            let ecdsaSignature: P384.Signing.ECDSASignature
            do {
                publicKey = try P384.Signing.PublicKey(
                    x963Representation: Data(publicKeyBytes)
                )
            } catch {
                throw invalidKeyError
            }
            do {
                ecdsaSignature = try P384.Signing.ECDSASignature(
                    rawRepresentation: Data(normalizedSignature)
                )
            } catch {
                throw invalidSignatureError
            }
            isValid = publicKey.isValidSignature(
                ecdsaSignature,
                for: Data(signedBytes)
            )
        case .nistp521:
            let publicKey: P521.Signing.PublicKey
            let ecdsaSignature: P521.Signing.ECDSASignature
            do {
                publicKey = try P521.Signing.PublicKey(
                    x963Representation: Data(publicKeyBytes)
                )
            } catch {
                throw invalidKeyError
            }
            do {
                ecdsaSignature = try P521.Signing.ECDSASignature(
                    rawRepresentation: Data(normalizedSignature)
                )
            } catch {
                throw invalidSignatureError
            }
            isValid = publicKey.isValidSignature(
                ecdsaSignature,
                for: Data(signedBytes)
            )
        }

        guard isValid else {
            throw invalidSignatureError
        }
    }

    private func parseEd25519HostKey(_ hostKey: [UInt8]) throws -> SSHParsedEd25519HostKey {
        var reader = SSHWireReader(bytes: hostKey)
        let algorithmName = try reader.readUTF8String()

        guard algorithmName == Self.ed25519AlgorithmName else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: Self.ed25519AlgorithmName,
                received: algorithmName
            )
        }

        let publicKey = try reader.readString()
        guard publicKey.count == 32 else {
            throw SSHHostKeyVerificationError.invalidEd25519PublicKeyLength(
                publicKey.count
            )
        }

        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidEd25519PublicKey
        }

        return SSHParsedEd25519HostKey(
            algorithmName: algorithmName,
            publicKey: publicKey
        )
    }

    private func parseEd25519Signature(_ signature: [UInt8]) throws -> SSHParsedEd25519Signature {
        var reader = SSHWireReader(bytes: signature)
        let algorithmName = try reader.readUTF8String()

        guard algorithmName == Self.ed25519AlgorithmName else {
            throw SSHHostKeyVerificationError.unsupportedSignatureAlgorithm(
                algorithmName
            )
        }

        let signatureBytes = try reader.readString()
        guard signatureBytes.count == 64 else {
            throw SSHHostKeyVerificationError.invalidEd25519SignatureLength(
                signatureBytes.count
            )
        }

        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidSignature
        }

        return SSHParsedEd25519Signature(
            algorithmName: algorithmName,
            signatureBytes: signatureBytes
        )
    }

    private func parseEd25519HostCertificate(
        _ hostKey: [UInt8]
    ) throws -> SSHParsedEd25519HostCertificate {
        var reader = SSHWireReader(bytes: hostKey)
        let algorithmName = try reader.readUTF8String()

        guard algorithmName == Self.ed25519CertificateAlgorithmName else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: Self.ed25519CertificateAlgorithmName,
                received: algorithmName
            )
        }

        _ = try reader.readString() // nonce
        let publicKey = try reader.readString()
        guard publicKey.count == 32 else {
            throw SSHHostKeyVerificationError.invalidEd25519PublicKeyLength(
                publicKey.count
            )
        }

        _ = try reader.readUInt64() // serial
        let certificateType = try reader.readUInt32()
        guard certificateType == Self.hostCertificateType else {
            throw SSHHostKeyVerificationError.invalidHostCertificateType(
                certificateType
            )
        }

        _ = try reader.readString() // key id
        let validPrincipalsBlob = try reader.readString()
        let validPrincipals = try self.parseValidPrincipals(validPrincipalsBlob)
        let validAfter = try reader.readUInt64()
        let validBefore = try reader.readUInt64()
        _ = try reader.readString() // critical options
        _ = try reader.readString() // extensions
        _ = try reader.readString() // reserved
        let certificateAuthorityKey = try reader.readString()
        let signedBytes = Array(hostKey.prefix(reader.readIndex))
        let certificateSignature = try reader.readString()

        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidHostCertificate
        }

        return SSHParsedEd25519HostCertificate(
            algorithmName: algorithmName,
            publicKey: publicKey,
            validPrincipals: validPrincipals,
            validAfter: validAfter,
            validBefore: validBefore,
            certificateAuthorityKey: certificateAuthorityKey,
            signedBytes: signedBytes,
            certificateSignature: certificateSignature
        )
    }

    private func parseECDSAHostCertificate(
        _ hostKey: [UInt8],
        expectedAlgorithmName: String
    ) throws -> SSHParsedECDSAHostCertificate {
        guard let expectedCurve = Self.ecdsaCertificateCurve(
            algorithmName: expectedAlgorithmName
        ) else {
            throw SSHHostKeyVerificationError.unsupportedHostKeyAlgorithm(
                expectedAlgorithmName
            )
        }

        var reader = SSHWireReader(bytes: hostKey)
        let algorithmName = try reader.readUTF8String()

        guard algorithmName == expectedAlgorithmName else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: expectedAlgorithmName,
                received: algorithmName
            )
        }

        _ = try reader.readString() // nonce
        let curveName = try reader.readUTF8String()
        guard curveName == expectedCurve.rawValue else {
            throw SSHHostKeyVerificationError.invalidECDSACurveName(
                expected: expectedCurve.rawValue,
                received: curveName
            )
        }

        let publicKey = try reader.readString()
        _ = try reader.readUInt64() // serial
        let certificateType = try reader.readUInt32()
        guard certificateType == Self.hostCertificateType else {
            throw SSHHostKeyVerificationError.invalidHostCertificateType(
                certificateType
            )
        }

        _ = try reader.readString() // key id
        let validPrincipalsBlob = try reader.readString()
        let validPrincipals = try self.parseValidPrincipals(validPrincipalsBlob)
        let validAfter = try reader.readUInt64()
        let validBefore = try reader.readUInt64()
        _ = try reader.readString() // critical options
        _ = try reader.readString() // extensions
        _ = try reader.readString() // reserved
        let certificateAuthorityKey = try reader.readString()
        let signedBytes = Array(hostKey.prefix(reader.readIndex))
        let certificateSignature = try reader.readString()

        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidHostCertificate
        }

        return SSHParsedECDSAHostCertificate(
            algorithmName: algorithmName,
            curve: expectedCurve,
            publicKey: publicKey,
            validPrincipals: validPrincipals,
            validAfter: validAfter,
            validBefore: validBefore,
            certificateAuthorityKey: certificateAuthorityKey,
            signedBytes: signedBytes,
            certificateSignature: certificateSignature
        )
    }

    private func parseValidPrincipals(_ payload: [UInt8]) throws -> [String] {
        var reader = SSHWireReader(bytes: payload)
        var principals: [String] = []

        while !reader.isAtEnd {
            principals.append(try reader.readUTF8String())
        }

        return principals
    }

    private func parseECDSAHostKey(_ hostKey: [UInt8]) throws -> SSHParsedECDSAHostKey {
        var reader = SSHWireReader(bytes: hostKey)
        let algorithmName = try reader.readUTF8String()
        guard SSHECDSACurve(algorithmName: algorithmName) != nil else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: "ecdsa-sha2-*",
                received: algorithmName
            )
        }

        let curveName = try reader.readUTF8String()
        let publicKey = try reader.readString()
        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidECDSAPublicKey
        }

        return SSHParsedECDSAHostKey(
            algorithmName: algorithmName,
            curveName: curveName,
            publicKey: publicKey
        )
    }

    private func parseECDSASignature(_ signature: [UInt8]) throws -> SSHParsedECDSASignature {
        var reader = SSHWireReader(bytes: signature)
        let algorithmName = try reader.readUTF8String()
        guard let curve = SSHECDSACurve(algorithmName: algorithmName) else {
            throw SSHHostKeyVerificationError.unsupportedSignatureAlgorithm(
                algorithmName
            )
        }

        let signatureBytes = try reader.readString()
        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidECDSASignature
        }

        var signatureReader = SSHWireReader(bytes: signatureBytes)
        let r = try signatureReader.readMPInt()
        let s = try signatureReader.readMPInt()
        guard signatureReader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidECDSASignature
        }

        return SSHParsedECDSASignature(
            algorithmName: algorithmName,
            curve: curve,
            r: r,
            s: s
        )
    }

    private func parseRSAHostKey(_ hostKey: [UInt8]) throws -> SSHParsedRSAHostKey {
        var reader = SSHWireReader(bytes: hostKey)
        let algorithmName = try reader.readUTF8String()

        guard algorithmName == Self.rsaHostKeyAlgorithmName else {
            throw SSHHostKeyVerificationError.hostKeyAlgorithmMismatch(
                expected: Self.rsaHostKeyAlgorithmName,
                received: algorithmName
            )
        }

        let publicExponent = try reader.readMPInt()
        let modulus = try reader.readMPInt()
        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidRSAPublicKey
        }

        return SSHParsedRSAHostKey(
            algorithmName: algorithmName,
            publicExponent: self.unsignedMagnitude(publicExponent),
            modulus: self.unsignedMagnitude(modulus)
        )
    }

    private func parseRSASignature(_ signature: [UInt8]) throws -> SSHParsedRSASignature {
        var reader = SSHWireReader(bytes: signature)
        let algorithmName = try reader.readUTF8String()
        guard SSHRSAHostKeySignatureAlgorithm(rawValue: algorithmName) != nil else {
            throw SSHHostKeyVerificationError.unsupportedSignatureAlgorithm(
                algorithmName
            )
        }

        let signatureBytes = try reader.readString()
        guard reader.isAtEnd else {
            throw SSHHostKeyVerificationError.invalidSignature
        }

        return SSHParsedRSASignature(
            algorithmName: algorithmName,
            signatureBytes: signatureBytes
        )
    }

    private func normalizedECDSASignature(
        r: SSHMPInt,
        s: SSHMPInt,
        coordinateByteCount: Int
    ) throws -> [UInt8] {
        try self.normalizedECDSAComponent(
            r,
            coordinateByteCount: coordinateByteCount
        ) + self.normalizedECDSAComponent(
            s,
            coordinateByteCount: coordinateByteCount
        )
    }

    private func normalizedECDSAComponent(
        _ value: SSHMPInt,
        coordinateByteCount: Int
    ) throws -> [UInt8] {
        let magnitude = self.unsignedMagnitude(value)
        guard magnitude.count <= coordinateByteCount else {
            throw SSHHostKeyVerificationError.invalidECDSASignature
        }
        return Array(repeating: 0, count: coordinateByteCount - magnitude.count) + magnitude
    }

    private func unsignedMagnitude(_ value: SSHMPInt) -> [UInt8] {
        value.encodedBytes.first == 0
            ? Array(value.encodedBytes.dropFirst())
            : value.encodedBytes
    }

    private static func ecdsaCertificateCurve(
        algorithmName: String
    ) -> SSHECDSACurve? {
        guard algorithmName.hasSuffix(Self.certificateAlgorithmSuffix) else {
            return nil
        }

        let plainAlgorithmName = String(
            algorithmName.dropLast(Self.certificateAlgorithmSuffix.count)
        )
        return SSHECDSACurve(algorithmName: plainAlgorithmName)
    }
}

private struct SSHParsedEd25519HostKey: Equatable, Sendable {
    let algorithmName: String
    let publicKey: [UInt8]
}

private struct SSHParsedEd25519Signature: Equatable, Sendable {
    let algorithmName: String
    let signatureBytes: [UInt8]
}

private struct SSHParsedEd25519HostCertificate: Equatable, Sendable {
    let algorithmName: String
    let publicKey: [UInt8]
    let validPrincipals: [String]
    let validAfter: UInt64
    let validBefore: UInt64
    let certificateAuthorityKey: [UInt8]
    let signedBytes: [UInt8]
    let certificateSignature: [UInt8]
}

private struct SSHParsedECDSAHostCertificate: Equatable, Sendable {
    let algorithmName: String
    let curve: SSHECDSACurve
    let publicKey: [UInt8]
    let validPrincipals: [String]
    let validAfter: UInt64
    let validBefore: UInt64
    let certificateAuthorityKey: [UInt8]
    let signedBytes: [UInt8]
    let certificateSignature: [UInt8]
}

private struct SSHParsedECDSAHostKey: Equatable, Sendable {
    let algorithmName: String
    let curveName: String
    let publicKey: [UInt8]
}

private struct SSHParsedECDSASignature: Equatable, Sendable {
    let algorithmName: String
    let curve: SSHECDSACurve
    let r: SSHMPInt
    let s: SSHMPInt
}

private struct SSHParsedRSAHostKey: Equatable, Sendable {
    let algorithmName: String
    let publicExponent: [UInt8]
    let modulus: [UInt8]
}

private struct SSHParsedRSASignature: Equatable, Sendable {
    let algorithmName: String
    let signatureBytes: [UInt8]
}

private enum SSHRSAHostKeySignatureAlgorithm: String {
    case rsaSHA512 = "rsa-sha2-512"
    case rsaSHA256 = "rsa-sha2-256"
    case sshRSA = "ssh-rsa"

    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .rsaSHA512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .rsaSHA256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .sshRSA:
            return .rsaSignatureMessagePKCS1v15SHA1
        }
    }
}
