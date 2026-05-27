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
func openSSHEd25519PrivateKeyParsesSamplePEM() throws {
    let privateKey = try SSHEd25519PrivateKey(openSSHPrivateKey: sampleOpenSSHEd25519PrivateKeyPEM)

    #expect(privateKey.rawRepresentation == sampleOpenSSHEd25519PrivateKeyRawRepresentation)
    #expect(
        try privateKey.authorizedKeyLine(comment: "unit-test")
            == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID6QPR7hayueaiL3PfJ6Vs2kU85Lv+s8Qz09wKiFo595 unit-test"
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsEd25519CredentialFromOpenSSHPEM() throws {
    let method = try SSHAuthenticationMethod.ed25519PrivateKey(
        openSSHPrivateKey: sampleOpenSSHEd25519PrivateKeyPEM
    )

    #expect(method == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodAutoDetectsOpenSSHPrivateKeyPEM() throws {
    let rsaPrivateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let p256 = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let p256PEM = makeOpenSSHECDSAPrivateKeyPEM(
        curve: .nistp256,
        rawRepresentation: Array(p256.rawRepresentation),
        publicKey: Array(p256.publicKey.x963Representation)
    )

    #expect(
        try SSHAuthenticationMethod.openSSHPrivateKey(sampleOpenSSHEd25519PrivateKeyPEM)
            == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation)
    )
    #expect(
        try SSHAuthenticationMethod.openSSHPrivateKey(sampleOpenSSHRSAPrivateKeyPEM)
            == .rsaPrivateKey(pkcs1DERRepresentation: rsaPrivateKey.pkcs1DERRepresentation)
    )
    #expect(
        try SSHAuthenticationMethod.openSSHPrivateKey(p256PEM)
            == .ecdsaP256PrivateKey(rawRepresentation: Array(p256.rawRepresentation))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsOpenSSHPrivateKeys() throws {
    let rsaPrivateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(sampleOpenSSHEd25519PrivateKeyPEM)
            == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation)
    )
    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(sampleOpenSSHRSAPrivateKeyPEM)
            == .rsaPrivateKey(pkcs1DERRepresentation: rsaPrivateKey.pkcs1DERRepresentation)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsTraditionalUnencryptedRSA() throws {
    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let pem = makePrivateKeyPEM(
        type: "RSA PRIVATE KEY",
        derBytes: privateKey.pkcs1DERRepresentation
    )

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(pem)
            == .rsaPrivateKey(pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsOpenSSLStylePKCS8Keys() throws {
    let rsaPrivateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let p256 = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let ed25519PKCS8PEM = makePKCS8PrivateKeyPEM(
        algorithmIdentifier: makeAlgorithmIdentifier(oid: oidEd25519),
        privateKeyBytes: derOctetString(sampleOpenSSHEd25519PrivateKeyRawRepresentation)
    )
    let rsaPKCS8PEM = makePKCS8PrivateKeyPEM(
        algorithmIdentifier: makeAlgorithmIdentifier(oid: oidRSAEncryption, parameters: derNull()),
        privateKeyBytes: rsaPrivateKey.pkcs1DERRepresentation
    )
    let ecdsaPKCS8PEM = makePKCS8PrivateKeyPEM(
        algorithmIdentifier: makeAlgorithmIdentifier(
            oid: oidECPublicKey,
            parameters: derObjectIdentifier(oidPrime256v1)
        ),
        privateKeyBytes: makeECPrivateKeyDER(
            curveOID: oidPrime256v1,
            rawRepresentation: Array(p256.rawRepresentation)
        )
    )

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(ed25519PKCS8PEM)
            == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation)
    )
    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(rsaPKCS8PEM)
            == .rsaPrivateKey(pkcs1DERRepresentation: rsaPrivateKey.pkcs1DERRepresentation)
    )
    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(ecdsaPKCS8PEM)
            == .ecdsaP256PrivateKey(rawRepresentation: Array(p256.rawRepresentation))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsTraditionalOpenSSHEC() throws {
    let p256 = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let pem = makePrivateKeyPEM(
        type: "EC PRIVATE KEY",
        derBytes: makeECPrivateKeyDER(
            curveOID: oidPrime256v1,
            rawRepresentation: Array(p256.rawRepresentation)
        )
    )

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(pem)
            == .ecdsaP256PrivateKey(rawRepresentation: Array(p256.rawRepresentation))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsTraditionalRSAFromFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_rsa_legacy")
    try makePrivateKeyPEM(
        type: "RSA PRIVATE KEY",
        derBytes: privateKey.pkcs1DERRepresentation
    ).write(to: privateKeyURL, atomically: true, encoding: .utf8)

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(contentsOfFile: privateKeyURL.path)
            == .rsaPrivateKey(pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsMalformedTraditionalRSA() throws {
    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(
            """
            -----BEGIN RSA PRIVATE KEY-----
            not-base64
            -----END RSA PRIVATE KEY-----
            """
        )
        Issue.record("Expected malformed traditional RSA PEM to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .invalidPrivateKeyPEM)
    }

    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(
            makePrivateKeyPEM(type: "RSA PRIVATE KEY", derBytes: [0x30, 0x00])
        )
        Issue.record("Expected invalid traditional RSA DER to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .invalidRSAPrivateKeyPEM)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsEncryptedTraditionalRSA() throws {
    let method = try SSHAuthenticationMethod.privateKeyPEM(
        sampleEncryptedTraditionalRSAPrivateKeyPEM,
        passphrase: sampleEncryptedTraditionalRSAPrivateKeyPassphrase
    )

    guard case let .rsaPrivateKey(pkcs1DERRepresentation) = method else {
        Issue.record("Expected encrypted traditional RSA PEM to load as RSA")
        return
    }

    let components = try SSHRSAPKCS1DERCodec.parsePrivateKey(pkcs1DERRepresentation)
    #expect(components.modulus.count >= 128)
    #expect(components.publicExponent == [0x01, 0x00, 0x01])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsEncryptedTraditionalRSAWithoutPassphrase() throws {
    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(sampleEncryptedTraditionalRSAPrivateKeyPEM)
        Issue.record("Expected encrypted traditional RSA PEM without a passphrase to be rejected")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .missingLegacyPrivateKeyPEMPassphrase("RSA PRIVATE KEY")
        )
        #expect(
            (error as NSError).localizedDescription
                .contains("requires a passphrase")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsEncryptedTraditionalRSAWithWrongPassphrase() throws {
    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(
            sampleEncryptedTraditionalRSAPrivateKeyPEM,
            passphrase: "wrong-passphrase"
        )
        Issue.record("Expected encrypted traditional RSA PEM with wrong passphrase to be rejected")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .incorrectLegacyPrivateKeyPEMPassphrase("RSA PRIVATE KEY")
        )
        #expect(
            (error as NSError).localizedDescription
                .contains("could not be decrypted")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsUnsupportedEncryptedTraditionalRSACipher() throws {
    let pem = makePrivateKeyPEM(
        type: "RSA PRIVATE KEY",
        headers: [
            "Proc-Type: 4,ENCRYPTED",
            "DEK-Info: CAMELLIA-256-CBC,0123456789ABCDEF0123456789ABCDEF",
        ],
        derBytes: [0x30, 0x00]
    )

    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(pem, passphrase: "ignored")
        Issue.record("Expected unsupported encrypted traditional RSA PEM cipher to be rejected")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .unsupportedLegacyPrivateKeyPEMCipher("CAMELLIA-256-CBC")
        )
        #expect(
            (error as NSError).localizedDescription
                .contains("Unsupported encrypted legacy private-key PEM cipher")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsEncryptedPKCS8WithReadableError() throws {
    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(
            makePrivateKeyPEM(type: "ENCRYPTED PRIVATE KEY", derBytes: [0x30, 0x00])
        )
        Issue.record("Expected encrypted PKCS#8 PEM to be rejected")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .encryptedLegacyPrivateKeyPEMUnsupported("ENCRYPTED PRIVATE KEY")
        )
        #expect(
            (error as NSError).localizedDescription
                .contains("Encrypted OpenSSL-style private-key PEM is not supported")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMRejectsUnsupportedContainerWithReadableError() throws {
    do {
        _ = try SSHAuthenticationMethod.privateKeyPEM(
            makePrivateKeyPEM(type: "DSA PRIVATE KEY", derBytes: [0x30, 0x00])
        )
        Issue.record("Expected unsupported legacy DSA PEM to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .unsupportedPrivateKeyPEMType("DSA PRIVATE KEY"))
        #expect((error as NSError).localizedDescription.contains("Unsupported private-key PEM type"))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodErrorsExposeReadableLocalizedDescriptions() throws {
    let description = (SSHAuthenticationMethodError.invalidOpenSSHPrivateKeyPEM as NSError)
        .localizedDescription

    #expect(description.contains("OpenSSH private-key PEM"))
    #expect(description.contains("SSHAuthenticationMethodError") == false)
}

#if os(macOS)
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodPrivateKeyPEMLoadsLocalOpenSSLGeneratedKeys() throws {
    let version = try runOpenSSL(arguments: ["version"])
    guard version.exitStatus == 0 else {
        return
    }

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let ed25519URL = temporaryDirectory.appendingPathComponent("id_ed25519_pkcs8.pem")
    let rsaURL = temporaryDirectory.appendingPathComponent("id_rsa_pkcs8.pem")
    let encryptedTraditionalRSAURL = temporaryDirectory
        .appendingPathComponent("id_rsa_traditional_encrypted.pem")
    let ecdsaPKCS8URL = temporaryDirectory.appendingPathComponent("id_ecdsa_pkcs8.pem")
    let ecdsaTraditionalURL = temporaryDirectory.appendingPathComponent("id_ecdsa_traditional.pem")

    let generations = [
        try runOpenSSL(arguments: [
            "genpkey",
            "-algorithm",
            "ed25519",
            "-out",
            ed25519URL.path,
        ]),
        try runOpenSSL(arguments: [
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            rsaURL.path,
        ]),
        try runOpenSSL(arguments: [
            "genrsa",
            "-traditional",
            "-aes256",
            "-passout",
            "pass:traversio-test",
            "-out",
            encryptedTraditionalRSAURL.path,
            "1024",
        ]),
        try runOpenSSL(arguments: [
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            ecdsaPKCS8URL.path,
        ]),
        try runOpenSSL(arguments: [
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            ecdsaTraditionalURL.path,
        ]),
    ]

    guard generations.allSatisfy({ $0.exitStatus == 0 }) else {
        return
    }

    guard case let .ed25519PrivateKey(ed25519Raw) = try SSHAuthenticationMethod.privateKeyPEM(
        contentsOfFile: ed25519URL.path
    ) else {
        Issue.record("Expected OpenSSL Ed25519 PKCS#8 key to load as Ed25519")
        return
    }
    #expect(ed25519Raw.count == 32)

    guard case let .rsaPrivateKey(pkcs1DERRepresentation) = try SSHAuthenticationMethod.privateKeyPEM(
        contentsOfFile: rsaURL.path
    ) else {
        Issue.record("Expected OpenSSL RSA PKCS#8 key to load as RSA")
        return
    }
    #expect((try SSHRSAPKCS1DERCodec.parsePrivateKey(pkcs1DERRepresentation)).modulus.count >= 128)

    guard case let .rsaPrivateKey(encryptedPKCS1DERRepresentation) = try SSHAuthenticationMethod
        .privateKeyPEM(
            contentsOfFile: encryptedTraditionalRSAURL.path,
            passphrase: "traversio-test"
        ) else {
        Issue.record("Expected OpenSSL encrypted traditional RSA key to load as RSA")
        return
    }
    #expect(
        (try SSHRSAPKCS1DERCodec.parsePrivateKey(encryptedPKCS1DERRepresentation))
            .modulus.count >= 128
    )

    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(contentsOfFile: ecdsaPKCS8URL.path).ecdsaCurveName
            == "nistp256"
    )
    #expect(
        try SSHAuthenticationMethod.privateKeyPEM(contentsOfFile: ecdsaTraditionalURL.path).ecdsaCurveName
            == "nistp256"
    )
}
#endif

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoParsesUnencryptedEnvelopeMetadata() throws {
    let info = try SSHOpenSSHPrivateKeyInfo.parse(sampleOpenSSHEd25519PrivateKeyPEM)

    #expect(info.cipherName == "none")
    #expect(info.cipher == .none)
    #expect(info.kdfName == "none")
    #expect(info.keyDerivationFunction == .none)
    #expect(info.isEncrypted == false)
    #expect(info.keyCount == 1)
    #expect(info.publicKeys.count == 1)
    #expect(info.primaryPublicKey.index == 0)
    #expect(info.primaryPublicKey.algorithmName == "ssh-ed25519")
    #expect(info.primaryPublicKey.algorithm == .ed25519)
    #expect(info.primaryPublicKey.publicKeyBlob.isEmpty == false)
    #expect(info.primaryPublicKey.fingerprintSHA256.count == 64)
    #expect(
        info.primaryPublicKey.authorizedKeyLine(comment: "unit-test")
            == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID6QPR7hayueaiL3PfJ6Vs2kU85Lv+s8Qz09wKiFo595 unit-test"
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoReadsEncryptedEnvelopeWithoutPassphrase() throws {
    let info = try SSHOpenSSHPrivateKeyInfo.parse(sampleEncryptedOpenSSHEd25519PrivateKeyPEM)

    #expect(info.cipherName == "aes256-ctr")
    #expect(info.cipher == .aes256CTR)
    #expect(info.kdfName == "bcrypt")
    #expect(info.isEncrypted)
    #expect(info.primaryPublicKey.algorithm == .ed25519)

    guard case let .bcrypt(salt, rounds) = info.keyDerivationFunction else {
        Issue.record("Expected encrypted OpenSSH key metadata to include bcrypt KDF options")
        return
    }
    #expect(salt.count == 16)
    #expect(rounds == 24)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoLoadsFromFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_ed25519")
    try sampleOpenSSHEd25519PrivateKeyPEM.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )

    let info = try SSHOpenSSHPrivateKeyInfo.parse(contentsOfFile: privateKeyURL.path)

    #expect(info.primaryPublicKey.algorithm == .ed25519)
    #expect(info.primaryPublicKey.algorithmName == "ssh-ed25519")
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test(
    "OpenSSH private key info classifies generated key algorithms",
    arguments: supportedKeyPairAlgorithmCases
)
func openSSHPrivateKeyInfoClassifiesGeneratedKeyAlgorithms(
    _ testCase: OpenSSHKeyPairAlgorithmTestCase
) throws {
    let keyPair = try SSHOpenSSHKeyPair.generate(
        algorithm: testCase.algorithm,
        comment: "metadata-\(testCase.name)"
    )

    let info = try SSHOpenSSHPrivateKeyInfo.parse(keyPair.privateKeyPEM)

    #expect(info.primaryPublicKey.algorithm == expectedMetadataAlgorithm(for: testCase.algorithm))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoParsesMultiplePublicKeyBlobs() throws {
    let firstPublicKey = makeOpenSSHEd25519PublicKeyBlob(
        Array(repeating: 0x11, count: 32)
    )
    let secondPublicKey = makeUnknownOpenSSHPublicKeyBlob(
        algorithmName: "ssh-future@example.com",
        payload: [0x01, 0x02, 0x03]
    )
    let pem = makeOpenSSHPrivateKeyInfoPEM(
        publicKeyBlobs: [firstPublicKey, secondPublicKey],
        privateKeyBlock: [0x01, 0x02]
    )

    let info = try SSHOpenSSHPrivateKeyInfo.parse(pem)

    #expect(info.keyCount == 2)
    #expect(info.publicKeys.map(\.algorithmName) == ["ssh-ed25519", "ssh-future@example.com"])
    #expect(info.publicKeys[0].algorithm == .ed25519)
    #expect(info.publicKeys[1].algorithm == .unknown("ssh-future@example.com"))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoPreservesUnknownCipherKDFAndAlgorithmMetadata() throws {
    var kdfOptionsWriter = SSHWireWriter()
    kdfOptionsWriter.write(string: [0x01, 0x02, 0x03])
    let pem = makeOpenSSHPrivateKeyInfoPEM(
        cipherName: "aes512-ctr@example.com",
        kdfName: "future-kdf@example.com",
        kdfOptions: kdfOptionsWriter.bytes,
        publicKeyBlobs: [
            makeUnknownOpenSSHPublicKeyBlob(
                algorithmName: "ssh-future@example.com",
                payload: [0x04, 0x05]
            ),
        ],
        privateKeyBlock: [0x06, 0x07]
    )

    let info = try SSHOpenSSHPrivateKeyInfo.parse(pem)

    #expect(info.cipher == .unknown("aes512-ctr@example.com"))
    #expect(
        info.keyDerivationFunction
            == .unknown(name: "future-kdf@example.com", options: kdfOptionsWriter.bytes)
    )
    #expect(info.primaryPublicKey.algorithm == .unknown("ssh-future@example.com"))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoClassifiesCertificateAlgorithmNames() throws {
    let pem = makeOpenSSHPrivateKeyInfoPEM(
        publicKeyBlobs: [
            makeUnknownOpenSSHPublicKeyBlob(
                algorithmName: "ssh-ed25519-cert-v01@openssh.com",
                payload: [0x01, 0x02]
            ),
        ],
        privateKeyBlock: [0x03]
    )

    let info = try SSHOpenSSHPrivateKeyInfo.parse(pem)

    #expect(
        info.primaryPublicKey.algorithm
            == .certificate(
                algorithmName: "ssh-ed25519-cert-v01@openssh.com",
                baseAlgorithmName: "ssh-ed25519"
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHPrivateKeyInfoRejectsMalformedEnvelopeMetadata() throws {
    do {
        _ = try SSHOpenSSHPrivateKeyInfo.parse("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
        Issue.record("Expected legacy PEM key to be rejected by the OpenSSH metadata parser")
    } catch {
        #expect(error as? SSHOpenSSHPrivateKeyInfoError == .invalidPEM)
    }

    do {
        _ = try SSHOpenSSHPrivateKeyInfo.parse(
            makeOpenSSHPrivateKeyInfoPEM(publicKeyBlobs: [])
        )
        Issue.record("Expected empty OpenSSH public-key list to be rejected")
    } catch {
        #expect(error as? SSHOpenSSHPrivateKeyInfoError == .invalidKeyCount(0))
    }

    do {
        _ = try SSHOpenSSHPrivateKeyInfo.parse(
            makeOpenSSHPrivateKeyInfoPEM(
                cipherName: "aes256-ctr",
                kdfName: "none",
                publicKeyBlobs: [
                    makeOpenSSHEd25519PublicKeyBlob(Array(repeating: 0x11, count: 32)),
                ]
            )
        )
        Issue.record("Expected encrypted cipher with no KDF to be rejected")
    } catch {
        #expect(error as? SSHOpenSSHPrivateKeyInfoError == .invalidEnvelope)
    }

    do {
        _ = try SSHOpenSSHPrivateKeyInfo.parse(
            makeOpenSSHPrivateKeyInfoPEM(
                publicKeyBlobs: [
                    makeOpenSSHEd25519PublicKeyBlob(Array(repeating: 0x11, count: 31)),
                ]
            )
        )
        Issue.record("Expected invalid Ed25519 public-key length to be rejected")
    } catch {
        #expect(error as? SSHOpenSSHPrivateKeyInfoError == .invalidPublicKey(index: 0))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHRSAPrivateKeyParsesSamplePEM() throws {
    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)

    #expect(!privateKey.pkcs1DERRepresentation.isEmpty)
    #expect(
        try privateKey.authorizedKeyLine(comment: "unit-test")
            == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDLV5lUTt7FrADseB/CGhEZzpoojjEW5y8+ePvLppmK3MmMI18ud6vxzpK3bwZLYkVSyfJYI0HmIuGhdu7yMrW6wb84gbq8C31Xoe9EORcIUuGSvDKdNSM1SjlhDquRblDFB8kToqXyx1lqrXecXylxIUOL0jE+u0rU1967pDJx+w== unit-test"
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsRSACredentialFromOpenSSHPEM() throws {
    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let method = try SSHAuthenticationMethod.rsaPrivateKey(
        openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM
    )

    #expect(
        method == .rsaPrivateKey(
            pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodLoadsRSACredentialFromOpenSSHPrivateKeyFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKey = try SSHRSAPrivateKey(openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM)
    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_rsa")
    try sampleOpenSSHRSAPrivateKeyPEM.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )

    let method = try SSHAuthenticationMethod.rsaPrivateKey(
        contentsOfOpenSSHPrivateKeyFile: privateKeyURL.path
    )

    #expect(
        method == .rsaPrivateKey(
            pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodLoadsEd25519CredentialFromOpenSSHPrivateKeyFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_ed25519")
    try sampleOpenSSHEd25519PrivateKeyPEM.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )

    let method = try SSHAuthenticationMethod.ed25519PrivateKey(
        contentsOfOpenSSHPrivateKeyFile: privateKeyURL.path
    )

    #expect(method == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func openSSHEd25519EncryptedPrivateKeyParsesSamplePEM() throws {
    let privateKey = try SSHEd25519PrivateKey(
        openSSHPrivateKey: sampleEncryptedOpenSSHEd25519PrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(privateKey.rawRepresentation == sampleOpenSSHEd25519PrivateKeyRawRepresentation)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsEd25519CredentialFromEncryptedOpenSSHPEM() throws {
    let method = try SSHAuthenticationMethod.ed25519PrivateKey(
        openSSHPrivateKey: sampleEncryptedOpenSSHEd25519PrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(method == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodLoadsEncryptedEd25519CredentialFromOpenSSHPrivateKeyFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_ed25519")
    try sampleEncryptedOpenSSHEd25519PrivateKeyPEM.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )

    let method = try SSHAuthenticationMethod.ed25519PrivateKey(
        contentsOfOpenSSHPrivateKeyFile: privateKeyURL.path,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(method == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodRejectsEncryptedOpenSSHPrivateKeyWithoutPassphrase() throws {
    do {
        _ = try SSHAuthenticationMethod.ed25519PrivateKey(
            openSSHPrivateKey: sampleEncryptedOpenSSHEd25519PrivateKeyPEM
        )
        Issue.record("Expected encrypted OpenSSH private key without passphrase to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .missingOpenSSHPrivateKeyPassphrase)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodRejectsEncryptedOpenSSHPrivateKeyWithWrongPassphrase() throws {
    do {
        _ = try SSHAuthenticationMethod.ed25519PrivateKey(
            openSSHPrivateKey: sampleEncryptedOpenSSHEd25519PrivateKeyPEM,
            passphrase: "wrong-passphrase"
        )
        Issue.record("Expected encrypted OpenSSH private key with wrong passphrase to be rejected")
    } catch {
        #expect(error as? SSHAuthenticationMethodError == .incorrectOpenSSHPrivateKeyPassphrase)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsEd25519CredentialFromAES256CBCEncryptedOpenSSHPEM() throws {
    let method = try SSHAuthenticationMethod.ed25519PrivateKey(
        openSSHPrivateKey: sampleAES256CBCEncryptedOpenSSHEd25519PrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(method == .ed25519PrivateKey(rawRepresentation: sampleOpenSSHEd25519PrivateKeyRawRepresentation))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodRejectsUnsupportedEncryptedOpenSSHPrivateKeyCipher() throws {
    let pem = makeOpenSSHPrivateKeyInfoPEM(
        cipherName: "chacha20-poly1305@openssh.com",
        kdfName: "bcrypt",
        kdfOptions: [0x01, 0x02],
        publicKeyBlobs: [
            makeOpenSSHEd25519PublicKeyBlob(Array(repeating: 0x11, count: 32)),
        ],
        privateKeyBlock: [0x03]
    )

    do {
        _ = try SSHAuthenticationMethod.ed25519PrivateKey(openSSHPrivateKey: pem)
        Issue.record("Expected unsupported encrypted OpenSSH private key cipher to be rejected")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .unsupportedOpenSSHPrivateKeyCipher("chacha20-poly1305@openssh.com")
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsRSACredentialFromEncryptedOpenSSHPEM() throws {
    let privateKey = try SSHRSAPrivateKey(
        openSSHPrivateKey: sampleEncryptedOpenSSHRSAPrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )
    let method = try SSHAuthenticationMethod.rsaPrivateKey(
        openSSHPrivateKey: sampleEncryptedOpenSSHRSAPrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(
        method == .rsaPrivateKey(
            pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsECDSACredentialsFromOpenSSHPEM() throws {
    let p256 = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let p384 = try P384.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x30)))
    let p521 = try P521.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x42)))

    let p256PEM = makeOpenSSHECDSAPrivateKeyPEM(
        curve: .nistp256,
        rawRepresentation: Array(p256.rawRepresentation),
        publicKey: Array(p256.publicKey.x963Representation)
    )
    let p384PEM = makeOpenSSHECDSAPrivateKeyPEM(
        curve: .nistp384,
        rawRepresentation: Array(p384.rawRepresentation),
        publicKey: Array(p384.publicKey.x963Representation)
    )
    let p521PEM = makeOpenSSHECDSAPrivateKeyPEM(
        curve: .nistp521,
        rawRepresentation: Array(p521.rawRepresentation),
        publicKey: Array(p521.publicKey.x963Representation)
    )

    #expect(
        try SSHAuthenticationMethod.ecdsaPrivateKey(openSSHPrivateKey: p256PEM)
            == .ecdsaP256PrivateKey(rawRepresentation: Array(p256.rawRepresentation))
    )
    #expect(
        try SSHAuthenticationMethod.ecdsaPrivateKey(openSSHPrivateKey: p384PEM)
            == .ecdsaP384PrivateKey(rawRepresentation: Array(p384.rawRepresentation))
    )
    #expect(
        try SSHAuthenticationMethod.ecdsaPrivateKey(openSSHPrivateKey: p521PEM)
            == .ecdsaP521PrivateKey(rawRepresentation: Array(p521.rawRepresentation))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodLoadsECDSACredentialFromOpenSSHPrivateKeyFile() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let pem = makeOpenSSHECDSAPrivateKeyPEM(
        curve: .nistp256,
        rawRepresentation: Array(privateKey.rawRepresentation),
        publicKey: Array(privateKey.publicKey.x963Representation)
    )
    let privateKeyURL = temporaryDirectory.appendingPathComponent("id_ecdsa")
    try pem.write(
        to: privateKeyURL,
        atomically: true,
        encoding: .utf8
    )

    let method = try SSHAuthenticationMethod.ecdsaPrivateKey(
        contentsOfOpenSSHPrivateKeyFile: privateKeyURL.path
    )

    #expect(
        method == .ecdsaP256PrivateKey(rawRepresentation: Array(privateKey.rawRepresentation))
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func authenticationMethodBuildsECDSACredentialFromEncryptedOpenSSHPEM() throws {
    let method = try SSHAuthenticationMethod.ecdsaPrivateKey(
        openSSHPrivateKey: sampleEncryptedOpenSSHECDSAPrivateKeyPEM,
        passphrase: sampleEncryptedOpenSSHPrivateKeyPassphrase
    )

    #expect(
        method == .ecdsaP256PrivateKey(
            rawRepresentation: sampleEncryptedOpenSSHECDSAPrivateKeyRawRepresentation
        )
    )
}

private let sampleOpenSSHEd25519PrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA+kD0e4Wsrnmoi9z3yelbNpFPOS7/rPEM9PcCohaOfeQAAAKCG1mF4htZh
eAAAAAtzc2gtZWQyNTUxOQAAACA+kD0e4Wsrnmoi9z3yelbNpFPOS7/rPEM9PcCohaOfeQ
AAAEDAPa3g9OmxrAvoWMvWSZWtRBLFIXGCAlmPlJpHZjOZrj6QPR7hayueaiL3PfJ6Vs2k
U85Lv+s8Qz09wKiFo595AAAAGlRyYXZlcnNpbyBFZDI1NTE5IHRlc3Qga2V5AQID
-----END OPENSSH PRIVATE KEY-----
"""

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

private let sampleEncryptedOpenSSHPrivateKeyPassphrase = "traversio-pass"

private let sampleEncryptedTraditionalRSAPrivateKeyPassphrase = "traversio-legacy-rsa"

private let sampleEncryptedTraditionalRSAPrivateKeyPEM = """
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,D4067B3EBB5DDCCCDE5F665C7FDE1314

vIyKYpcWrfPiNXKuDexCr6a5HDgO/CI+Wuek50kkTeHlk3SIcUoIvh1damSBgYj1
WpjAu7wTS9oOVngKb7DhSSvYWcrVhTFxXxpddxcdQj7egqZPaN9sr4pF56ZE770W
cBW+nlTr3FuxAo3MKm2WewI0vAcKp7OcvnjUdpA6fN5jawEWmmtcWiuz/9TA7cK7
etuM0Lt9i1t1RcyLNNJMwHtpuVjxdr20C30zem5NIsAri05sd7TWHvxMZADURziP
YbsrWQFPjTiugGoHuS8zo+bwY7WB+GnzvL8I/AnI/OWmUhvVWdHSvnYTiJHC2gtP
9WR0q4jVcNQMBolJMNtvbG+xTD0AYvasRbZ9dkBpJVVooqFWWkIY9VGlsbGqw8BX
o/72RwxAxLuj8RtgeQtTFG0k3uyFpdM9h7coro2ewhdvdRB1APIaMYavjvve6P7f
6pW1BZ4AAFSucXoI+t/DuKSLXWzSOum3dRsF6pBeBQEwBDbE2bRk1tt+HrMy1969
xgzHaSdi4oiRBpe0nK2Il5LnjmkdGPWWbmTRQfION8e+7MTQip7PvyUASIDiti18
x+4MURsIcWB1wGChfauBHCaeYWn+zx1fMZN6qpgHWbsIkPECOFOG0GQ6sKV8+pNg
GA/+ATjaHdZtaQ4t2CgMpVRn4MbZk47lQnhWJR6aWeG/sRGhc/KcqwwVQD4S8gqe
WUnTrV7AzCe0jKS7d37gZOKq6ah2qvJZIHLVPzKEWaBhc8NLzov9hsJob/oTZnHD
yvzNLS5RhPrrmvuNYuwnIJtQRi/dFPIzLyPVwMVDSXsCQxWDHbWLI1bnnSzUgU77
-----END RSA PRIVATE KEY-----
"""

private let sampleEncryptedOpenSSHEd25519PrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDmtH5qn5
8Shg2WAjcuCmdxAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAID6QPR7hayueaiL3
PfJ6Vs2kU85Lv+s8Qz09wKiFo595AAAAsBgiemyC/AdYCFo2tmZjX1Hv+hIMZlZMbLEjxV
F9SK6JnEHMstjSC8JWPGNqkwNMD+Zex7qsAstUxwc7XkvSXAKnOrvcT0TkzryLET0nfhoe
F2WstYc7Li42GKe1SXQRBLZMsqjiZn1xnZ74nNCJtetrX5CqgfYZhVoYGoVDxxTEQddOmr
eFwzJgJqpJxHFLrx5JkA7r6u3UqAZm6uKwrHkles9Xpz86G64teDYQsYsx
-----END OPENSSH PRIVATE KEY-----
"""

private let sampleAES256CBCEncryptedOpenSSHEd25519PrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABA/5A47v/
ynUThPkRSu4a2uAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAID6QPR7hayueaiL3
PfJ6Vs2kU85Lv+s8Qz09wKiFo595AAAAsFAdhPEKoFxWApJ/7HgAF/hofWqROCwg7nEqmA
s3k2kMwP2FDnsAa9/i18HfqaQWMmJoIBWy3vxHu/TSx5rNUYIBve+ND750+lYsAYp95EOj
aHQXNh2mNWCxCTbsXW2VzA99tAjD8oUFk5YRjnGuc9pX/W7VuqV5FKKRF9h0kM3Jur/Vji
JqLDTld0tVIZGIA1Hlh7WJYlU28Gf9mZynfQbzzVeu+VJH0Ji+hC9oSJCC
-----END OPENSSH PRIVATE KEY-----
"""

private let sampleEncryptedOpenSSHRSAPrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBJCMfOXG
Sa7gOJsj95YuSUAAAAGAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQDLV5lUTt7F
rADseB/CGhEZzpoojjEW5y8+ePvLppmK3MmMI18ud6vxzpK3bwZLYkVSyfJYI0HmIuGhdu
7yMrW6wb84gbq8C31Xoe9EORcIUuGSvDKdNSM1SjlhDquRblDFB8kToqXyx1lqrXecXylx
IUOL0jE+u0rU1967pDJx+wAAAgCQUp5vnS2MYgOT1IqYt2UmYSdpZN9nGKmSTfx8S34myF
w5TbZj1tPnixEzbWmjX6M6KBgPL2a4F7sZ2ZvtTB+eaoTYmYa7LYo9qPQgiMrs1bPZiwOT
CvkXcDLGAwy5TG6ziXNaEAOppsPEVd+wEucrwSEtO3ESMAjO4H7BOQiPsfoL3cZH0rYINL
E3lW4apB8igAU5G45Nsye7zAYi/BjynsNygf2amxMi45Q71i2zbWhe2sop5QKXtdnxQpBS
XlvKiUiDPr9FT9kkvdCA65BPsp+oM/pr3NCrkqCNJLZ5WRHeOQFL2vOiYp1VJcujZVoG0Y
uoXf8UOtIb/+j9KlWSRqbH+x/a+YlW3B9+mlwtpn7mCJIRfp3BPVQIIs7h2SrDEvur9ktX
paGWrc8jDsuK1y6pi3ZNtMlh/9vvEFQDIBAxFkOFE+J5R2dob1nNyS3qsdWyWMgeBBkK3b
tFafKYhijkzY2tPs9RnVUt0OBc9JUca7kuerB8tvZN6V7BtnPMFFSxsfgu/9gSdw2J/hnz
8jxvj7ksYgF837KtOXGfnDHfVbYLS9cfBIOAY6dA5nOO8i3WsmtlGwTGoIT3EN7M251vwa
NY48u0/P+QWc3SQ+PRooKSzwnMJbY9BPa5f/S3NrAlWwOuQbD+6tULYec6yF0kgKw7pTyL
V2CJSlQVaw==
-----END OPENSSH PRIVATE KEY-----
"""

private let sampleEncryptedOpenSSHECDSAPrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDevlmB6X
QO3X0Ry+vgW9M+AAAAGAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBCvnzI8qSYqkfCLmyXIZ3NhZq0gFbYRE2hoUV4iZkCKmqI5S/NGsFl0NJG
DjAKqWzxpqwuMYutQO/sXbMUeHgzEAAACwBJIWYBMD/3c6lHu25BW1hKLYHBAlcA6NjkdM
IOX9dy3oz1fsltNiR6jWhm69idZD7GaoAs0AxgsnQsMidLXdVaRinAfWqeACv7DC4MGpy4
2JezgdgKSiA+XcSqrJpWDCtPK3DI0mlhcWo7maWv+nIjr6UWVEaRYw3JBEU5/TESLiNk3a
hexzHI/t85I6O5mGDTxQumcfjL1V65uQgG6ZNJKAAcTE8sAQkR9T0b5IY/E=
-----END OPENSSH PRIVATE KEY-----
"""

private let sampleOpenSSHEd25519PrivateKeyRawRepresentation: [UInt8] = [
    0xc0, 0x3d, 0xad, 0xe0, 0xf4, 0xe9, 0xb1, 0xac,
    0x0b, 0xe8, 0x58, 0xcb, 0xd6, 0x49, 0x95, 0xad,
    0x44, 0x12, 0xc5, 0x21, 0x71, 0x82, 0x02, 0x59,
    0x8f, 0x94, 0x9a, 0x47, 0x66, 0x33, 0x99, 0xae,
]

private let sampleEncryptedOpenSSHECDSAPrivateKeyRawRepresentation: [UInt8] = [
    0x41, 0xed, 0x24, 0x08, 0x02, 0x67, 0x65, 0x2a,
    0x16, 0xc5, 0x2c, 0x6d, 0xda, 0x4e, 0xf9, 0xc8,
    0x0b, 0x01, 0xf0, 0x13, 0xbc, 0x7d, 0x8b, 0xb4,
    0x8d, 0xce, 0xcd, 0x50, 0xb1, 0x0d, 0xe0, 0x55,
]

private func expectedMetadataAlgorithm(
    for algorithm: SSHOpenSSHKeyPair.Algorithm
) -> SSHOpenSSHPrivateKeyAlgorithm {
    switch algorithm {
    case .ed25519:
        return .ed25519
    case .ecdsaP256:
        return .ecdsa(curve: .nistp256)
    case .ecdsaP384:
        return .ecdsa(curve: .nistp384)
    case .ecdsaP521:
        return .ecdsa(curve: .nistp521)
    case let .rsa(bitCount):
        return .rsa(modulusBitCount: bitCount)
    }
}

private func makeOpenSSHPrivateKeyInfoPEM(
    cipherName: String = "none",
    kdfName: String = "none",
    kdfOptions: [UInt8] = [],
    publicKeyBlobs: [[UInt8]],
    privateKeyBlock: [UInt8] = []
) -> String {
    var writer = SSHWireWriter()
    writer.write(rawBytes: Array("openssh-key-v1".utf8) + [0])
    writer.write(utf8: cipherName)
    writer.write(utf8: kdfName)
    writer.write(string: kdfOptions)
    writer.write(uint32: UInt32(publicKeyBlobs.count))
    for publicKeyBlob in publicKeyBlobs {
        writer.write(string: publicKeyBlob)
    }
    writer.write(string: privateKeyBlock)

    return makeOpenSSHPrivateKeyPEM(encodedPayload: writer.bytes)
}

private func makeOpenSSHEd25519PublicKeyBlob(_ publicKey: [UInt8]) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: "ssh-ed25519")
    writer.write(string: publicKey)
    return writer.bytes
}

private func makeUnknownOpenSSHPublicKeyBlob(
    algorithmName: String,
    payload: [UInt8]
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: algorithmName)
    writer.write(string: payload)
    return writer.bytes
}

private func makeOpenSSHPrivateKeyPEM(
    cipherName: String,
    kdfName: String,
    kdfOptions: [UInt8],
    keyCount: UInt32
) -> String {
    var writer = SSHWireWriter()
    writer.write(rawBytes: Array("openssh-key-v1".utf8) + [0])
    writer.write(utf8: cipherName)
    writer.write(utf8: kdfName)
    writer.write(string: kdfOptions)
    writer.write(uint32: keyCount)

    return makeOpenSSHPrivateKeyPEM(encodedPayload: writer.bytes)
}

private func makeOpenSSHPrivateKeyPEM(encodedPayload: [UInt8]) -> String {
    let encoded = Data(encodedPayload).base64EncodedString()
    let lines = stride(from: 0, to: encoded.count, by: 70).map { startIndex -> String in
        let start = encoded.index(encoded.startIndex, offsetBy: startIndex)
        let end = encoded.index(start, offsetBy: min(70, encoded.count - startIndex))
        return String(encoded[start..<end])
    }

    return """
    -----BEGIN OPENSSH PRIVATE KEY-----
    \(lines.joined(separator: "\n"))
    -----END OPENSSH PRIVATE KEY-----
    """
}

private func makePrivateKeyPEM(
    type: String,
    headers: [String] = [],
    derBytes: [UInt8]
) -> String {
    let encoded = Data(derBytes).base64EncodedString()
    let lines = stride(from: 0, to: encoded.count, by: 64).map { startIndex -> String in
        let start = encoded.index(encoded.startIndex, offsetBy: startIndex)
        let end = encoded.index(start, offsetBy: min(64, encoded.count - startIndex))
        return String(encoded[start..<end])
    }
    let payload = (headers + lines).joined(separator: "\n")

    return """
    -----BEGIN \(type)-----
    \(payload)
    -----END \(type)-----
    """
}

private extension SSHAuthenticationMethod {
    var ecdsaCurveName: String? {
        switch self {
        case .ecdsaP256PrivateKey:
            return "nistp256"
        case .ecdsaP384PrivateKey:
            return "nistp384"
        case .ecdsaP521PrivateKey:
            return "nistp521"
        case .password,
             .passwordWithChangeResponse,
             .ed25519PrivateKey,
             .rsaPrivateKey,
             .publicKey,
             .keyboardInteractive:
            return nil
        }
    }
}

#if os(macOS)
private struct OpenSSLResult {
    let exitStatus: Int32
}

private func runOpenSSL(arguments: [String]) throws -> OpenSSLResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["openssl"] + arguments
    process.standardOutput = Pipe()
    process.standardError = Pipe()

    try process.run()
    process.waitUntilExit()

    return OpenSSLResult(exitStatus: process.terminationStatus)
}
#endif

private let oidRSAEncryption: [UInt64] = [1, 2, 840, 113_549, 1, 1, 1]
private let oidEd25519: [UInt64] = [1, 3, 101, 112]
private let oidECPublicKey: [UInt64] = [1, 2, 840, 10_045, 2, 1]
private let oidPrime256v1: [UInt64] = [1, 2, 840, 10_045, 3, 1, 7]

private func makePKCS8PrivateKeyPEM(
    algorithmIdentifier: [UInt8],
    privateKeyBytes: [UInt8]
) -> String {
    makePrivateKeyPEM(
        type: "PRIVATE KEY",
        derBytes: derSequence([
            derInteger(0),
            algorithmIdentifier,
            derOctetString(privateKeyBytes),
        ])
    )
}

private func makeAlgorithmIdentifier(
    oid: [UInt64],
    parameters: [UInt8] = []
) -> [UInt8] {
    derSequence([derObjectIdentifier(oid), parameters])
}

private func makeECPrivateKeyDER(
    curveOID: [UInt64],
    rawRepresentation: [UInt8]
) -> [UInt8] {
    derSequence([
        derInteger(1),
        derOctetString(rawRepresentation),
        derExplicit(tag: 0xa0, derObjectIdentifier(curveOID)),
    ])
}

private func derSequence(_ elements: [[UInt8]]) -> [UInt8] {
    derElement(tag: 0x30, payload: elements.flatMap { $0 })
}

private func derInteger(_ value: Int) -> [UInt8] {
    precondition(value >= 0)
    var value = value
    var bytes: [UInt8] = []
    repeat {
        bytes.insert(UInt8(value & 0xff), at: 0)
        value >>= 8
    } while value > 0
    if bytes[0] & 0x80 == 0x80 {
        bytes.insert(0, at: 0)
    }
    return derElement(tag: 0x02, payload: bytes)
}

private func derOctetString(_ bytes: [UInt8]) -> [UInt8] {
    derElement(tag: 0x04, payload: bytes)
}

private func derNull() -> [UInt8] {
    derElement(tag: 0x05, payload: [])
}

private func derObjectIdentifier(_ oid: [UInt64]) -> [UInt8] {
    precondition(oid.count >= 2)
    var payload = [UInt8(oid[0] * 40 + oid[1])]
    for component in oid.dropFirst(2) {
        payload += derBase128(component)
    }
    return derElement(tag: 0x06, payload: payload)
}

private func derExplicit(tag: UInt8, _ payload: [UInt8]) -> [UInt8] {
    derElement(tag: tag, payload: payload)
}

private func derElement(tag: UInt8, payload: [UInt8]) -> [UInt8] {
    [tag] + derLength(payload.count) + payload
}

private func derLength(_ length: Int) -> [UInt8] {
    precondition(length >= 0)
    if length < 0x80 {
        return [UInt8(length)]
    }

    var value = length
    var bytes: [UInt8] = []
    while value > 0 {
        bytes.insert(UInt8(value & 0xff), at: 0)
        value >>= 8
    }
    return [0x80 | UInt8(bytes.count)] + bytes
}

private func derBase128(_ value: UInt64) -> [UInt8] {
    var value = value
    var bytes = [UInt8(value & 0x7f)]
    value >>= 7
    while value > 0 {
        bytes.insert(UInt8(value & 0x7f) | 0x80, at: 0)
        value >>= 7
    }
    return bytes
}

private func makeOpenSSHECDSAPrivateKeyPEM(
    curve: SSHECDSACurve,
    rawRepresentation: [UInt8],
    publicKey: [UInt8],
    comment: String = "unit-test"
) -> String {
    var publicKeyWriter = SSHWireWriter()
    publicKeyWriter.write(utf8: curve.algorithmName)
    publicKeyWriter.write(utf8: curve.rawValue)
    publicKeyWriter.write(string: publicKey)

    var privateKeyWriter = SSHWireWriter()
    privateKeyWriter.write(uint32: 0x01020304)
    privateKeyWriter.write(uint32: 0x01020304)
    privateKeyWriter.write(utf8: curve.algorithmName)
    privateKeyWriter.write(utf8: curve.rawValue)
    privateKeyWriter.write(string: publicKey)
    privateKeyWriter.write(mpint: SSHMPInt(unsignedMagnitude: rawRepresentation))
    privateKeyWriter.write(utf8: comment)
    privateKeyWriter.write(rawBytes: [0x01, 0x02, 0x03, 0x04])

    var writer = SSHWireWriter()
    writer.write(rawBytes: Array("openssh-key-v1".utf8) + [0])
    writer.write(utf8: "none")
    writer.write(utf8: "none")
    writer.write(string: [])
    writer.write(uint32: 1)
    writer.write(string: publicKeyWriter.bytes)
    writer.write(string: privateKeyWriter.bytes)

    let encoded = Data(writer.bytes).base64EncodedString()
    let lines = stride(from: 0, to: encoded.count, by: 70).map { startIndex -> String in
        let start = encoded.index(encoded.startIndex, offsetBy: startIndex)
        let end = encoded.index(start, offsetBy: min(70, encoded.count - startIndex))
        return String(encoded[start..<end])
    }

    return """
    -----BEGIN OPENSSH PRIVATE KEY-----
    \(lines.joined(separator: "\n"))
    -----END OPENSSH PRIVATE KEY-----
    """
}
