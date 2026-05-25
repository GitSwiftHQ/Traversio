// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Testing
@testable import Traversio

struct ECDSAHostKeyVerificationCase: Sendable {
    let algorithmName: String
    let rawRepresentation: [UInt8]
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierAcceptsValidEd25519HostKeyAndSignature() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let exchangeHash = (0x80...0x9f).map(UInt8.init)
    let hostKey = makeEd25519HostKeyBlob(publicKey: Array(privateKey.publicKey.rawRepresentation))
    let signature = makeEd25519SignatureBlob(
        signatureBytes: Array(try privateKey.signature(for: exchangeHash))
    )

    let verified = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ssh-ed25519",
        exchangeHash: exchangeHash,
        hostKey: hostKey,
        signature: signature
    )

    #expect(verified.algorithmName == "ssh-ed25519")
    #expect(verified.publicKey == Array(privateKey.publicKey.rawRepresentation))
    #expect(verified.rawHostKey == hostKey)
    #expect(verified.rawSignature == signature)
    #expect(verified.certificate == nil)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierAcceptsValidEd25519HostCertificateAndExchangeSignature() throws {
    let privateKey = try SSHEd25519PrivateKey(
        openSSHPrivateKey: try loadBundledOpenSSHFixture(named: "ed25519_1")
    )
    let exchangeHash = (0xa0...0xbf).map(UInt8.init)
    let hostCertificate = try loadBundledOpenSSHAuthorizedKeyBlob(named: "ed25519_1-cert.pub")
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "ssh-ed25519"
    )

    let verified = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ssh-ed25519-cert-v01@openssh.com",
        exchangeHash: exchangeHash,
        hostKey: hostCertificate,
        signature: signature
    )

    #expect(verified.algorithmName == "ssh-ed25519-cert-v01@openssh.com")
    #expect(
        verified.publicKey
            == Array(try privateKey.makeRequest(algorithmName: "ssh-ed25519").publicKey.dropFirstString())
    )
    #expect(verified.rawHostKey == hostCertificate)
    #expect(verified.rawSignature == signature)
    #expect(
        verified.certificate
            == SSHVerifiedHostCertificate(
                validPrincipals: ["host1", "host2"],
                validAfter: 915_145_200,
                validBefore: 1_293_836_400,
                certificateAuthorityKey: try SSHTrustedHostKey(
                    rawRepresentation: try privateKey.makeRequest(
                        algorithmName: "ssh-ed25519"
                    ).publicKey
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierAcceptsValidECDSAHostCertificateAndExchangeSignature() throws {
    let privateKey = SSHECDSAPrivateKey.nistp256(
        rawRepresentation: sampleOpenSSHECDSATestKey1RawRepresentation
    )
    let exchangeHash = (0xc0...0xdf).map(UInt8.init)
    let hostCertificate = try loadBundledOpenSSHAuthorizedKeyBlob(named: "ecdsa_1-cert.pub")
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "ecdsa-sha2-nistp256"
    )

    let verified = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        exchangeHash: exchangeHash,
        hostKey: hostCertificate,
        signature: signature
    )

    #expect(verified.algorithmName == "ecdsa-sha2-nistp256-cert-v01@openssh.com")
    #expect(
        verified.publicKey
            == Array(
                try privateKey.makeRequest(
                    algorithmName: "ecdsa-sha2-nistp256"
                ).publicKey.dropFirstTwoStrings()
            )
    )
    #expect(verified.rawHostKey == hostCertificate)
    #expect(verified.rawSignature == signature)
    #expect(
        verified.certificate
            == SSHVerifiedHostCertificate(
                validPrincipals: ["host1", "host2"],
                validAfter: 915_145_200,
                validBefore: 1_293_836_400,
                certificateAuthorityKey: try SSHTrustedHostKey(
                    rawRepresentation: try privateKey.makeRequest(
                        algorithmName: "ecdsa-sha2-nistp256"
                    ).publicKey
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierRejectsNonHostOpenSSHCertificateType() throws {
    let privateKey = try SSHEd25519PrivateKey(
        openSSHPrivateKey: try loadBundledOpenSSHFixture(named: "ed25519_1")
    )
    var hostCertificate = try loadBundledOpenSSHAuthorizedKeyBlob(named: "ed25519_1-cert.pub")
    let certificateTypeOffset = try findCertificateTypeOffset(in: hostCertificate)
    hostCertificate.replaceSubrange(
        certificateTypeOffset..<(certificateTypeOffset + 4),
        with: [0x00, 0x00, 0x00, 0x01]
    )
    let signature = try privateKey.signUserAuthenticationRequest(
        (0xc0...0xdf).map(UInt8.init),
        algorithmName: "ssh-ed25519"
    )

    do {
        _ = try SSHHostKeyVerifier().verifyHostKey(
            expectedHostKeyAlgorithm: "ssh-ed25519-cert-v01@openssh.com",
            exchangeHash: (0xc0...0xdf).map(UInt8.init),
            hostKey: hostCertificate,
            signature: signature
        )
        Issue.record("Expected non-host certificate type to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyVerificationError
                == .invalidHostCertificateType(1)
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierRejectsSignatureAlgorithmMismatch() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let exchangeHash = (0x80...0x9f).map(UInt8.init)
    let hostKey = makeEd25519HostKeyBlob(publicKey: Array(privateKey.publicKey.rawRepresentation))
    let signature = makeSignatureBlob(
        algorithm: "rsa-sha2-512",
        bytes: Array(repeating: 0xaa, count: 64)
    )

    do {
        _ = try SSHHostKeyVerifier().verifyHostKey(
            expectedHostKeyAlgorithm: "ssh-ed25519",
            exchangeHash: exchangeHash,
            hostKey: hostKey,
            signature: signature
        )
        Issue.record("Expected unsupported-signature-algorithm error")
    } catch {
        #expect(
            error as? SSHHostKeyVerificationError
                == .unsupportedSignatureAlgorithm("rsa-sha2-512")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(arguments: ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"])
func hostKeyVerifierAcceptsValidRSAHostKeyAndSignature(
    signatureAlgorithm: String
) throws {
    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let exchangeHash = (0x20...0x3f).map(UInt8.init)
    let hostKey = try privateKey.makeRequest(
        algorithmName: signatureAlgorithm
    ).publicKey
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: signatureAlgorithm
    )

    let verified = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: signatureAlgorithm,
        exchangeHash: exchangeHash,
        hostKey: hostKey,
        signature: signature
    )

    #expect(verified.algorithmName == "ssh-rsa")
    #expect(verified.publicKey == privateKey.publicKeyPKCS1DERRepresentation)
    #expect(verified.rawHostKey == hostKey)
    #expect(verified.rawSignature == signature)
    #expect(verified.certificate == nil)
    #expect(SSHTrustedHostKey(verifiedHostKey: verified).algorithmName == "ssh-rsa")
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(arguments: [
    ECDSAHostKeyVerificationCase(
        algorithmName: "ecdsa-sha2-nistp256",
        rawRepresentation: (0x01...0x20).map(UInt8.init)
    ),
    ECDSAHostKeyVerificationCase(
        algorithmName: "ecdsa-sha2-nistp384",
        rawRepresentation: (0x01...0x30).map(UInt8.init)
    ),
    ECDSAHostKeyVerificationCase(
        algorithmName: "ecdsa-sha2-nistp521",
        rawRepresentation: (0x01...0x42).map(UInt8.init)
    ),
])
func hostKeyVerifierAcceptsValidECDSAHostKeyAndSignature(
    verificationCase: ECDSAHostKeyVerificationCase
) throws {
    let curve = try #require(SSHECDSACurve(algorithmName: verificationCase.algorithmName))
    let privateKey = SSHECDSAPrivateKey(
        curve: curve,
        rawRepresentation: verificationCase.rawRepresentation
    )
    let exchangeHash = (0x40...0x5f).map(UInt8.init)
    let hostKey = try privateKey.makeRequest(
        algorithmName: verificationCase.algorithmName
    ).publicKey
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: verificationCase.algorithmName
    )

    let verified = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: verificationCase.algorithmName,
        exchangeHash: exchangeHash,
        hostKey: hostKey,
        signature: signature
    )

    var hostKeyReader = SSHWireReader(bytes: hostKey)
    _ = try hostKeyReader.readUTF8String()
    _ = try hostKeyReader.readUTF8String()
    let rawPublicKey = try hostKeyReader.readString()
    #expect(hostKeyReader.isAtEnd)

    #expect(verified.algorithmName == verificationCase.algorithmName)
    #expect(verified.publicKey == rawPublicKey)
    #expect(verified.rawHostKey == hostKey)
    #expect(verified.rawSignature == signature)
    #expect(verified.certificate == nil)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierRejectsRSASignatureAlgorithmMismatch() throws {
    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let exchangeHash = (0x60...0x7f).map(UInt8.init)
    let hostKey = try privateKey.makeRequest(
        algorithmName: "rsa-sha2-512"
    ).publicKey
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "rsa-sha2-256"
    )

    do {
        _ = try SSHHostKeyVerifier().verifyHostKey(
            expectedHostKeyAlgorithm: "rsa-sha2-512",
            exchangeHash: exchangeHash,
            hostKey: hostKey,
            signature: signature
        )
        Issue.record("Expected RSA signature-algorithm mismatch error")
    } catch {
        #expect(
            error as? SSHHostKeyVerificationError
                == .signatureAlgorithmMismatch(
                    expected: "rsa-sha2-512",
                    received: "rsa-sha2-256"
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyVerifierRejectsECDSAHostKeyWithMismatchedCurveName() throws {
    let privateKey = SSHECDSAPrivateKey.nistp256(
        rawRepresentation: (0x01...0x20).map(UInt8.init)
    )
    let exchangeHash = (0x80...0x9f).map(UInt8.init)
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "ecdsa-sha2-nistp256"
    )

    var writer = SSHWireWriter()
    writer.write(utf8: "ecdsa-sha2-nistp256")
    writer.write(utf8: "nistp384")
    writer.write(
        string: try privateKey.makeRequest(
            algorithmName: "ecdsa-sha2-nistp256"
        ).publicKey.dropFirstTwoStrings()
    )

    do {
        _ = try SSHHostKeyVerifier().verifyHostKey(
            expectedHostKeyAlgorithm: "ecdsa-sha2-nistp256",
            exchangeHash: exchangeHash,
            hostKey: writer.bytes,
            signature: signature
        )
        Issue.record("Expected ECDSA curve-name mismatch error")
    } catch {
        #expect(
            error as? SSHHostKeyVerificationError
                == .invalidECDSACurveName(
                    expected: "nistp256",
                    received: "nistp384"
                )
        )
    }
}

private func makeEd25519HostKeyBlob(publicKey: [UInt8]) -> [UInt8] {
    makeBlob(algorithm: "ssh-ed25519", bytes: publicKey)
}

private func makeEd25519SignatureBlob(signatureBytes: [UInt8]) -> [UInt8] {
    makeBlob(algorithm: "ssh-ed25519", bytes: signatureBytes)
}

private func makeSignatureBlob(algorithm: String, bytes: [UInt8]) -> [UInt8] {
    makeBlob(algorithm: algorithm, bytes: bytes)
}

private func makeBlob(algorithm: String, bytes: [UInt8]) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: algorithm)
    writer.write(string: bytes)
    return writer.bytes
}

private extension Array where Element == UInt8 {
    func dropFirstTwoStrings() throws -> [UInt8] {
        var reader = SSHWireReader(bytes: self)
        _ = try reader.readUTF8String()
        _ = try reader.readUTF8String()
        return try reader.readString()
    }

    func dropFirstString() throws -> [UInt8] {
        var reader = SSHWireReader(bytes: self)
        _ = try reader.readUTF8String()
        return try reader.readString()
    }
}

private func findCertificateTypeOffset(in hostCertificate: [UInt8]) throws -> Int {
    var reader = SSHWireReader(bytes: hostCertificate)
    _ = try reader.readUTF8String()
    _ = try reader.readString()
    _ = try reader.readString()
    _ = try reader.readUInt64()
    return reader.readIndex
}

private let sampleOpenSSHRSAPrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAy1eZVE7exawA7HgfwhoRGc6aKI4xFucvPnj7y6aZitzJjCNfLner
8c6St28GS2JFUsnyWCNB5iLhoXbu8jK1usG/OIG6vAt9V6HvRDkXCFLhkrwynTUjNUo5YQ
6rkW5QxQfJE6Kl8sdZaq13nF8pcSFDi9IxPrtK1Nfeu6QycfsAAAH4to4I7raOCO4AAAAH
c3NoLXJzYQAAAIEAy1eZVE7exawA7HgfwhoRGc6aKI4xFucvPnj7y6aZitzJjCNfLner8c
6St28GS2JFUsnyWCNB5iLhoXbu8jK1usG/OIG6vAt9V6HvRDkXCFLhkrwynTUjNUo5YQ6r
kW5QxQfJE6Kl8sdZaq13nF8pcSFDi9IxPrtK1Nfeu6QycfsAAAADAQABAAAAgF8o+ZqY5m
w/mJcRiFs/86zOIRrFoHeFbXihCcU+jDCOLswkaZDHdHJPKB4sGRgCP0sFMyLILTjULh9w
F1bFIIIVuGJ5/vJLBL9CGfdfFgzA8Kr6pMq1c7DrGc6mIz3/A1AygqcBY55ZJydOMr1gWb
1YVrWODomfBldE7bLt5PhhAAAAQAndVkxvO8hwyEFGGwF3faHIAe/OxVb+MjaU25//Pe1/
h/e6tlCk4w9CODpyV685gV394eYwMcGDcIkipTNUDZsAAABBAPVgd+8FvkV0kG9SF17YiX
6NoWJrybBVU01qIPYQLFfHoLMbPnhksQH009V8NRkryUnhQkOp6VY2HeI8XdF59YMAAABB
ANQlQcwBS+JjcKZXlT8638uvcT94FjmtujMTPxhOs8fYwux4ENyj2linRvxbh7NPOWk0Q2
gy5hnGfCLzLruzYCkAAAAAAQID
-----END OPENSSH PRIVATE KEY-----
"""

private let sampleOpenSSHECDSATestKey1RawRepresentation: [UInt8] = [
    0xf3, 0xcd, 0xc9, 0x40, 0x27, 0x8e, 0xf1, 0x6b,
    0xf9, 0xe4, 0xff, 0xee, 0xdf, 0xc8, 0xca, 0x3b,
    0x90, 0x41, 0xdf, 0xda, 0x2c, 0x58, 0x93, 0x63,
    0xdd, 0x8b, 0x07, 0xd8, 0x08, 0x8f, 0x2a, 0xcc,
]
