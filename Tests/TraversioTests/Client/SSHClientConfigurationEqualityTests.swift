// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Test
func keyboardInteractiveAuthenticationMethodsCompareBySubmethods() async throws {
    let lhs = SSHAuthenticationMethod.keyboardInteractive(
        submethods: ["pam", "otp"],
        responseProvider: { _ in ["left"] }
    )
    let rhs = SSHAuthenticationMethod.keyboardInteractive(
        submethods: ["pam", "otp"],
        responseProvider: { _ in ["right"] }
    )
    let differentSubmethods = SSHAuthenticationMethod.keyboardInteractive(
        submethods: ["pam"],
        responseProvider: { _ in ["right"] }
    )

    #expect(lhs == rhs)
    #expect(lhs != differentSubmethods)
}

@Test
func publicKeyAuthenticationMethodsCompareByAlgorithmsAndPublicKey() async throws {
    let lhs = SSHAuthenticationMethod.publicKey(
        algorithmNames: ["ssh-ed25519"],
        publicKey: [1, 2, 3],
        signatureProvider: { _ in [1] }
    )
    let rhs = SSHAuthenticationMethod.publicKey(
        algorithmNames: ["ssh-ed25519"],
        publicKey: [1, 2, 3],
        signatureProvider: { _ in [2] }
    )
    let differentAlgorithm = SSHAuthenticationMethod.publicKey(
        algorithmNames: ["rsa-sha2-512"],
        publicKey: [1, 2, 3],
        signatureProvider: { _ in [2] }
    )
    let differentPublicKey = SSHAuthenticationMethod.publicKey(
        algorithmNames: ["ssh-ed25519"],
        publicKey: [1, 2, 4],
        signatureProvider: { _ in [2] }
    )

    #expect(lhs == rhs)
    #expect(lhs != differentAlgorithm)
    #expect(lhs != differentPublicKey)
}

@Test
func clientConfigurationEqualityIncludesKeyboardInteractiveSubmethods() async throws {
    let lhs = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .keyboardInteractive(
            submethods: ["pam"],
            responseProvider: { _ in ["first"] }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let rhs = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .keyboardInteractive(
            submethods: ["pam"],
            responseProvider: { _ in ["second"] }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let differentSubmethods = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .keyboardInteractive(
            submethods: ["otp"],
            responseProvider: { _ in ["second"] }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(lhs == rhs)
    #expect(lhs != differentSubmethods)
}

@Test
func clientConfigurationStoresOrderedAuthenticationMethods() async throws {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authenticationMethods: [
            .password("s3cr3t"),
            .keyboardInteractive(
                submethods: [],
                responseProvider: { _ in ["s3cr3t"] }
            ),
        ],
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.authentication == .password("s3cr3t"))
    #expect(
        configuration.authenticationMethods == [
            .password("s3cr3t"),
            .keyboardInteractive(
                submethods: [],
                responseProvider: { _ in [] }
            ),
        ]
    )
}

@Test
func proxyJumpHostStoresOrderedAuthenticationMethods() async throws {
    let jumpHost = SSHProxyJumpHost(
        host: "bastion.example.com",
        username: "jumper",
        authenticationMethods: [
            .password("jump"),
            .keyboardInteractive(
                submethods: ["pam"],
                responseProvider: { _ in ["jump"] }
            ),
        ],
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(jumpHost.authentication == .password("jump"))
    #expect(
        jumpHost.authenticationMethods == [
            .password("jump"),
            .keyboardInteractive(
                submethods: ["pam"],
                responseProvider: { _ in [] }
            ),
        ]
    )
}
