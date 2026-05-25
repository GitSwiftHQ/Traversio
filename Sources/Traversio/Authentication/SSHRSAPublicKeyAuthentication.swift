// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Security

package enum SSHRSAPrivateKeyError: Error, Equatable, Sendable {
    case invalidPKCS1PrivateKey
    case invalidRSAPrivateKey
    case unsupportedSignatureAlgorithm(String)
}

private enum SSHRSASignatureAlgorithm: String, CaseIterable, Sendable {
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
package struct SSHRSAPrivateKey: Equatable, Sendable {
    package let pkcs1DERRepresentation: [UInt8]

    let publicKeyPKCS1DERRepresentation: [UInt8]
    let publicKeyBlob: [UInt8]

    package static func generate(bitCount: Int) throws -> SSHRSAPrivateKey {
        guard bitCount >= 1024, bitCount.isMultiple(of: 8) else {
            throw SSHAuthenticationMethodError.invalidOpenSSHRSAKeyBitCount(bitCount)
        }

        var error: Unmanaged<CFError>?
        let attributes = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bitCount,
            kSecAttrIsPermanent as String: false,
        ] as CFDictionary
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            throw SSHAuthenticationMethodError.invalidOpenSSHRSAKeyBitCount(bitCount)
        }

        error = nil
        guard let pkcs1DERRepresentation = SecKeyCopyExternalRepresentation(
            privateKey,
            &error
        ) as Data? else {
            throw SSHAuthenticationMethodError.invalidOpenSSHPrivateKey
        }

        return try SSHRSAPrivateKey(
            pkcs1DERRepresentation: Array(pkcs1DERRepresentation)
        )
    }

    package init(pkcs1DERRepresentation: [UInt8]) throws {
        let components: SSHRSAPKCS1DERCodec.PrivateKeyComponents
        do {
            components = try SSHRSAPKCS1DERCodec.parsePrivateKey(pkcs1DERRepresentation)
            _ = try Self.makePrivateSecKey(pkcs1DERRepresentation: pkcs1DERRepresentation)
        } catch let error as SSHRSAPrivateKeyError {
            throw error
        } catch {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        self.pkcs1DERRepresentation = pkcs1DERRepresentation
        self.publicKeyPKCS1DERRepresentation = SSHRSAPKCS1DERCodec.encodePublicKey(
            modulus: components.modulus,
            publicExponent: components.publicExponent
        )
        self.publicKeyBlob = Self.makePublicKeyBlob(
            modulus: components.modulus,
            publicExponent: components.publicExponent
        )
    }

    package func authorizedKeyLine(comment: String = "traversio-probe") throws -> String {
        "ssh-rsa \(Data(self.publicKeyBlob).base64EncodedString()) \(comment)"
    }

    func publicSecKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        let attributes = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ] as CFDictionary

        guard let key = SecKeyCreateWithData(
            Data(self.publicKeyPKCS1DERRepresentation) as CFData,
            attributes,
            &error
        ) else {
            throw SSHRSAPrivateKeyError.invalidRSAPrivateKey
        }

        return key
    }

    private static func makePublicKeyBlob(
        modulus: [UInt8],
        publicExponent: [UInt8]
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: "ssh-rsa")
        writer.write(mpint: SSHMPInt(unsignedMagnitude: publicExponent))
        writer.write(mpint: SSHMPInt(unsignedMagnitude: modulus))
        return writer.bytes
    }

    private static func makePrivateSecKey(
        pkcs1DERRepresentation: [UInt8]
    ) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let attributes = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ] as CFDictionary

        guard let key = SecKeyCreateWithData(
            Data(pkcs1DERRepresentation) as CFData,
            attributes,
            &error
        ) else {
            throw SSHRSAPrivateKeyError.invalidRSAPrivateKey
        }

        return key
    }
}
extension SSHRSAPrivateKey: SSHPublicKeyAuthenticationPrivateKey {
    package var supportedAlgorithmNames: [String] {
        SSHRSASignatureAlgorithm.allCases.map(\.rawValue)
    }

    package func makeRequest(
        algorithmName: String
    ) throws -> SSHPublicKeyAuthenticationRequest {
        guard SSHRSASignatureAlgorithm(rawValue: algorithmName) != nil else {
            throw SSHRSAPrivateKeyError.unsupportedSignatureAlgorithm(algorithmName)
        }

        return SSHPublicKeyAuthenticationRequest(
            algorithmName: algorithmName,
            publicKey: self.publicKeyBlob,
            signature: nil
        )
    }

    package func signUserAuthenticationRequest(
        _ bytes: [UInt8],
        algorithmName: String
    ) throws -> [UInt8] {
        guard let signatureAlgorithm = SSHRSASignatureAlgorithm(rawValue: algorithmName) else {
            throw SSHRSAPrivateKeyError.unsupportedSignatureAlgorithm(algorithmName)
        }

        let privateKey = try Self.makePrivateSecKey(
            pkcs1DERRepresentation: self.pkcs1DERRepresentation
        )
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, signatureAlgorithm.secKeyAlgorithm) else {
            throw SSHRSAPrivateKeyError.unsupportedSignatureAlgorithm(algorithmName)
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            signatureAlgorithm.secKeyAlgorithm,
            Data(bytes) as CFData,
            &error
        ) as Data? else {
            throw SSHRSAPrivateKeyError.invalidRSAPrivateKey
        }

        var writer = SSHWireWriter()
        writer.write(utf8: algorithmName)
        writer.write(string: Array(signature))
        return writer.bytes
    }
}

enum SSHRSAPKCS1DERCodec {
    struct PrivateKeyComponents: Equatable {
        let modulus: [UInt8]
        let publicExponent: [UInt8]
        let privateExponent: [UInt8]
        let prime1: [UInt8]
        let prime2: [UInt8]
        let exponent1: [UInt8]
        let exponent2: [UInt8]
        let coefficient: [UInt8]
    }

    static func parsePrivateKey(_ der: [UInt8]) throws -> PrivateKeyComponents {
        var reader = SSHRSADERReader(bytes: der)
        let payload = try reader.readElement(tag: 0x30)
        guard reader.isAtEnd else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        var payloadReader = SSHRSADERReader(bytes: payload)
        try payloadReader.readVersionZero()

        let components = PrivateKeyComponents(
            modulus: try payloadReader.readPositiveInteger(),
            publicExponent: try payloadReader.readPositiveInteger(),
            privateExponent: try payloadReader.readPositiveInteger(),
            prime1: try payloadReader.readPositiveInteger(),
            prime2: try payloadReader.readPositiveInteger(),
            exponent1: try payloadReader.readPositiveInteger(),
            exponent2: try payloadReader.readPositiveInteger(),
            coefficient: try payloadReader.readPositiveInteger()
        )

        guard payloadReader.isAtEnd else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        return components
    }

    static func encodePrivateKey(
        modulus: [UInt8],
        publicExponent: [UInt8],
        privateExponent: [UInt8],
        prime1: [UInt8],
        prime2: [UInt8],
        exponent1: [UInt8],
        exponent2: [UInt8],
        coefficient: [UInt8]
    ) -> [UInt8] {
        self.encodeSequence(
            [
                self.encodeInteger(unsignedMagnitude: [0]),
                self.encodeInteger(unsignedMagnitude: modulus),
                self.encodeInteger(unsignedMagnitude: publicExponent),
                self.encodeInteger(unsignedMagnitude: privateExponent),
                self.encodeInteger(unsignedMagnitude: prime1),
                self.encodeInteger(unsignedMagnitude: prime2),
                self.encodeInteger(unsignedMagnitude: exponent1),
                self.encodeInteger(unsignedMagnitude: exponent2),
                self.encodeInteger(unsignedMagnitude: coefficient),
            ]
        )
    }

    static func encodePublicKey(
        modulus: [UInt8],
        publicExponent: [UInt8]
    ) -> [UInt8] {
        self.encodeSequence(
            [
                self.encodeInteger(unsignedMagnitude: modulus),
                self.encodeInteger(unsignedMagnitude: publicExponent),
            ]
        )
    }

    private static func encodeSequence(_ elements: [[UInt8]]) -> [UInt8] {
        let payload = elements.flatMap { $0 }
        return [0x30] + self.encodeLength(payload.count) + payload
    }

    private static func encodeInteger(unsignedMagnitude: [UInt8]) -> [UInt8] {
        let normalizedMagnitude = SSHRSAUnsignedInteger.normalized(unsignedMagnitude)
        let payload: [UInt8]

        if normalizedMagnitude.isEmpty {
            payload = [0]
        } else if normalizedMagnitude[0] & 0x80 == 0x80 {
            payload = [0] + normalizedMagnitude
        } else {
            payload = normalizedMagnitude
        }

        return [0x02] + self.encodeLength(payload.count) + payload
    }

    private static func encodeLength(_ length: Int) -> [UInt8] {
        guard length >= 0 else {
            return [0]
        }

        if length < 0x80 {
            return [UInt8(length)]
        }

        var value = length
        var octets: [UInt8] = []
        while value > 0 {
            octets.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }

        return [0x80 | UInt8(octets.count)] + octets
    }
}

private struct SSHRSADERReader {
    private let bytes: [UInt8]
    private var readIndex: Int = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool {
        self.readIndex == self.bytes.count
    }

    mutating func readElement(tag expectedTag: UInt8) throws -> [UInt8] {
        let actualTag = try self.readByte()
        guard actualTag == expectedTag else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        let length = try self.readLength()
        return try self.readBytes(count: length)
    }

    mutating func readVersionZero() throws {
        let encodedVersion = try self.readElement(tag: 0x02)
        guard encodedVersion == [0] else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }
    }

    mutating func readPositiveInteger() throws -> [UInt8] {
        let encodedInteger = try self.readElement(tag: 0x02)
        guard !encodedInteger.isEmpty else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        if encodedInteger[0] & 0x80 == 0x80 {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        let magnitude = SSHRSAUnsignedInteger.normalized(
            encodedInteger[0] == 0 ? Array(encodedInteger.dropFirst()) : encodedInteger
        )
        guard !magnitude.isEmpty else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        return magnitude
    }

    private mutating func readByte() throws -> UInt8 {
        let bytes = try self.readBytes(count: 1)
        return bytes[0]
    }

    private mutating func readLength() throws -> Int {
        let firstByte = try self.readByte()
        if firstByte & 0x80 == 0 {
            return Int(firstByte)
        }

        let byteCount = Int(firstByte & 0x7f)
        guard byteCount > 0 else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        let lengthOctets = try self.readBytes(count: byteCount)
        return lengthOctets.reduce(into: 0) { length, byte in
            length = (length << 8) | Int(byte)
        }
    }

    private mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0, self.readIndex + count <= self.bytes.count else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        let endIndex = self.readIndex + count
        let slice = Array(self.bytes[self.readIndex..<endIndex])
        self.readIndex = endIndex
        return slice
    }
}

enum SSHRSAUnsignedInteger {
    static func normalized(_ bytes: [UInt8]) -> [UInt8] {
        Array(bytes.drop { $0 == 0 })
    }

    static func subtractOne(_ bytes: [UInt8]) throws -> [UInt8] {
        var value = self.normalized(bytes)
        guard !value.isEmpty else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        var index = value.count - 1
        while true {
            if value[index] > 0 {
                value[index] &-= 1
                break
            }

            value[index] = 0xff
            guard index > 0 else {
                throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
            }
            index -= 1
        }

        return self.normalized(value)
    }

    static func mod(_ dividend: [UInt8], by divisor: [UInt8]) throws -> [UInt8] {
        let normalizedDivisor = self.normalized(divisor)
        guard !normalizedDivisor.isEmpty else {
            throw SSHRSAPrivateKeyError.invalidPKCS1PrivateKey
        }

        var remainder: [UInt8] = []
        for byte in self.normalized(dividend) {
            remainder = self.appendByte(byte, to: remainder)
            while self.compare(remainder, normalizedDivisor) >= 0 {
                remainder = self.subtract(remainder, normalizedDivisor)
            }
        }

        return self.normalized(remainder)
    }

    private static func appendByte(_ byte: UInt8, to bytes: [UInt8]) -> [UInt8] {
        let normalizedBytes = self.normalized(bytes)
        guard !normalizedBytes.isEmpty || byte != 0 else {
            return []
        }

        return normalizedBytes + [byte]
    }

    private static func compare(_ lhs: [UInt8], _ rhs: [UInt8]) -> Int {
        let lhs = self.normalized(lhs)
        let rhs = self.normalized(rhs)

        if lhs.count != rhs.count {
            return lhs.count < rhs.count ? -1 : 1
        }

        for (lhsByte, rhsByte) in zip(lhs, rhs) where lhsByte != rhsByte {
            return lhsByte < rhsByte ? -1 : 1
        }

        return 0
    }

    private static func subtract(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        let lhs = self.normalized(lhs)
        let rhs = self.normalized(rhs)
        precondition(self.compare(lhs, rhs) >= 0)

        var result = lhs
        var borrow = 0

        for offset in 0..<rhs.count {
            let lhsIndex = lhs.count - 1 - offset
            let rhsIndex = rhs.count - 1 - offset
            var difference = Int(result[lhsIndex]) - Int(rhs[rhsIndex]) - borrow

            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }

            result[lhsIndex] = UInt8(difference)
        }

        if borrow > 0 {
            var index = lhs.count - rhs.count - 1
            while true {
                if result[index] > 0 {
                    result[index] &-= 1
                    break
                }

                result[index] = 0xff
                precondition(index > 0)
                index -= 1
            }
        }

        return self.normalized(result)
    }
}
