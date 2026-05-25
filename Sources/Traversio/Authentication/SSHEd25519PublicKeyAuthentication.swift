// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation

package enum SSHEd25519PublicKeyAuthenticationError: Error, Equatable, Sendable {
    case invalidPrivateKeyLength(Int)
    case invalidPrivateKey
}
package struct SSHEd25519PrivateKey: Equatable, Sendable {
    private static let algorithmName = "ssh-ed25519"

    package let rawRepresentation: [UInt8]

    package init() {
        self.rawRepresentation = Array(Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    package init(rawRepresentation: [UInt8]) throws {
        guard rawRepresentation.count == 32 else {
            throw SSHEd25519PublicKeyAuthenticationError.invalidPrivateKeyLength(
                rawRepresentation.count
            )
        }

        do {
            _ = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(rawRepresentation))
        } catch {
            throw SSHEd25519PublicKeyAuthenticationError.invalidPrivateKey
        }

        self.rawRepresentation = rawRepresentation
    }

    package var supportedAlgorithmNames: [String] {
        [Self.algorithmName]
    }

    package func makeRequest(algorithmName: String) throws -> SSHPublicKeyAuthenticationRequest {
        _ = algorithmName
        let privateKey = try self.privateKey()

        var writer = SSHWireWriter()
        writer.write(utf8: Self.algorithmName)
        writer.write(string: Array(privateKey.publicKey.rawRepresentation))

        return SSHPublicKeyAuthenticationRequest(
            algorithmName: Self.algorithmName,
            publicKey: writer.bytes,
            signature: nil
        )
    }

    package func authorizedKeyLine(comment: String = "traversio-probe") throws -> String {
        let request = try self.makeRequest(algorithmName: Self.algorithmName)
        return "\(Self.algorithmName) \(Data(request.publicKey).base64EncodedString()) \(comment)"
    }

    package func signUserAuthenticationRequest(
        _ bytes: [UInt8],
        algorithmName: String
    ) throws -> [UInt8] {
        _ = algorithmName
        let privateKey = try self.privateKey()
        let signature = try Array(privateKey.signature(for: Data(bytes)))

        var writer = SSHWireWriter()
        writer.write(utf8: Self.algorithmName)
        writer.write(string: signature)
        return writer.bytes
    }

    private func privateKey() throws -> Curve25519.Signing.PrivateKey {
        do {
            return try Curve25519.Signing.PrivateKey(
                rawRepresentation: Data(self.rawRepresentation)
            )
        } catch {
            throw SSHEd25519PublicKeyAuthenticationError.invalidPrivateKey
        }
    }
}
extension SSHEd25519PrivateKey: SSHPublicKeyAuthenticationPrivateKey {}
