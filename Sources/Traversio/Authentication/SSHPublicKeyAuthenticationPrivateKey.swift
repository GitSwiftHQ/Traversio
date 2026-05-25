// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package protocol SSHPublicKeyAuthenticationPrivateKey: Sendable {
    var supportedAlgorithmNames: [String] { get }

    func makeRequest(algorithmName: String) throws -> SSHPublicKeyAuthenticationRequest
    func signUserAuthenticationRequest(_ bytes: [UInt8], algorithmName: String) throws -> [UInt8]
}

package struct SSHPublicKeyAuthenticationCredential: Sendable {
    package let supportedAlgorithmNames: [String]
    package let makeRequest: @Sendable (String) throws -> SSHPublicKeyAuthenticationRequest
    package let sign: @Sendable (SSHPublicKeyAuthenticationSigningRequest) async throws -> [UInt8]

    package init(privateKey: any SSHPublicKeyAuthenticationPrivateKey) {
        self.supportedAlgorithmNames = privateKey.supportedAlgorithmNames
        self.makeRequest = { algorithmName in
            try privateKey.makeRequest(algorithmName: algorithmName)
        }
        self.sign = { request in
            try privateKey.signUserAuthenticationRequest(
                request.signatureData,
                algorithmName: request.algorithmName
            )
        }
    }

    package init(
        algorithmNames: [String],
        publicKey: [UInt8],
        signatureProvider: @escaping @Sendable (
            SSHPublicKeyAuthenticationSigningRequest
        ) async throws -> [UInt8]
    ) {
        self.supportedAlgorithmNames = algorithmNames
        self.makeRequest = { algorithmName in
            SSHPublicKeyAuthenticationRequest(
                algorithmName: algorithmName,
                publicKey: publicKey,
                signature: nil
            )
        }
        self.sign = signatureProvider
    }
}
