// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func supportedAlgorithmsExposeCurrentTransportProfile() {
    let algorithms = SSHSupportedAlgorithms.currentProfile

    #expect(algorithms.keyExchangeAlgorithms == [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ])
    #expect(algorithms.serverHostKeyAlgorithms == [
        "ssh-ed25519",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ])
    #expect(algorithms.encryptionAlgorithmsClientToServer == [
        "aes128-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ])
    #expect(algorithms.encryptionAlgorithmsServerToClient == [
        "aes128-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ])
    #expect(algorithms.macAlgorithmsClientToServer == [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
    ])
    #expect(algorithms.macAlgorithmsServerToClient == [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
    ])
    #expect(algorithms.compressionAlgorithmsClientToServer == ["none"])
    #expect(algorithms.compressionAlgorithmsServerToClient == ["none"])
    #expect(algorithms.publicKeySignatureAlgorithms == [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ])
}

@Test
func supportedAlgorithmsReflectCompressionAndLegacyOptions() {
    let algorithms = SSHSupportedAlgorithms(
        compressionPreference: .delayedZlib,
        legacyAlgorithmOptions: .sshRSA
    )

    #expect(Array(algorithms.serverHostKeyAlgorithms.suffix(3)) == [
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    ])
    #expect(algorithms.compressionAlgorithmsClientToServer == ["zlib@openssh.com", "none"])
    #expect(algorithms.compressionAlgorithmsServerToClient == ["zlib@openssh.com", "none"])
    #expect(algorithms.publicKeySignatureAlgorithms == [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    ])
}

@Test
func clientConfigurationExposesEffectiveSupportedAlgorithms() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        compressionPreference: .zlib,
        legacyAlgorithmOptions: .sshRSA
    )

    #expect(
        configuration.supportedAlgorithms.algorithms(for: .compressionClientToServer)
            == ["zlib", "none"]
    )
    #expect(
        configuration.supportedAlgorithms.algorithms(for: .compressionServerToClient)
            == ["zlib", "none"]
    )
    #expect(configuration.supportedAlgorithms.algorithms(for: .serverHostKey).last == "ssh-rsa")
}

@Test
func proxyJumpHostExposesHopSupportedAlgorithms() {
    let hop = SSHProxyJumpHost(
        host: "jump.example.com",
        username: "jump",
        authentication: .password("secret"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        compressionPreference: .delayedZlib
    )

    #expect(
        hop.supportedAlgorithms.algorithms(for: .compressionClientToServer)
            == ["zlib@openssh.com", "none"]
    )
}
