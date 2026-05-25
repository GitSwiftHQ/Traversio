// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func clientKeyExchangePreferencesBuildExpectedMessageFromFixedCookie() throws {
    let message = try SSHClientKeyExchangePreferences.default.makeKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f)
    )

    #expect(message.cookie == Array(0x00...0x0f))
    #expect(
        message.keyExchangeAlgorithms == [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "ext-info-c",
            "kex-strict-c-v00@openssh.com",
        ]
    )
    #expect(
        message.serverHostKeyAlgorithms == [
            "ssh-ed25519",
            "ssh-ed25519-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "rsa-sha2-512",
            "rsa-sha2-256",
        ]
    )
    #expect(
        message.encryptionAlgorithmsClientToServer == [
            "aes128-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
        ]
    )
    #expect(
        message.macAlgorithmsClientToServer == [
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
        ]
    )
    #expect(message.compressionAlgorithmsClientToServer == ["none"])
    #expect(message.firstKeyExchangePacketFollows == false)
}

@Test
func clientKeyExchangePreferencesCanAppendLegacySSHRSAHostKeyAlgorithm() throws {
    let message = try SSHClientKeyExchangePreferences.default
        .withServerHostKeyAlgorithms(
            SSHLegacyAlgorithmOptions.sshRSA.preferredServerHostKeyAlgorithms
        )
        .makeKeyExchangeInitMessage(cookie: Array(0x20...0x2f))

    #expect(message.serverHostKeyAlgorithms.last == "ssh-rsa")
    #expect(message.serverHostKeyAlgorithms.filter { $0 == "ssh-rsa" }.count == 1)
}

@Test
func clientReexchangePreferencesOmitExtensionMarkers() throws {
    let message = try SSHClientKeyExchangePreferences.default.makeReexchangeKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f)
    )

    #expect(
        message.keyExchangeAlgorithms == [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
        ]
    )
}

@Test
func clientKeyExchangePreferencesCanOverrideCompressionAlgorithms() throws {
    let message = try SSHClientKeyExchangePreferences.default
        .withCompressionAlgorithms(
            clientToServer: ["zlib@openssh.com", "none"],
            serverToClient: ["zlib@openssh.com", "none"]
        )
        .makeKeyExchangeInitMessage(cookie: Array(0x20...0x2f))

    #expect(message.compressionAlgorithmsClientToServer == ["zlib@openssh.com", "none"])
    #expect(message.compressionAlgorithmsServerToClient == ["zlib@openssh.com", "none"])
}

@Test
func algorithmNegotiatorAllowsOpenSSHAESGCMWithoutCommonMAC() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-gcm@openssh.com"],
        encryptionAlgorithmsServerToClient: ["aes128-gcm@openssh.com"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-512"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-gcm@openssh.com"],
        encryptionAlgorithmsServerToClient: ["aes128-gcm@openssh.com"],
        macAlgorithmsClientToServer: ["umac-64-etm@openssh.com"],
        macAlgorithmsServerToClient: ["umac-128-etm@openssh.com"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )

    #expect(negotiation.algorithms.encryptionAlgorithmClientToServer == "aes128-gcm@openssh.com")
    #expect(negotiation.algorithms.encryptionAlgorithmServerToClient == "aes128-gcm@openssh.com")
    #expect(negotiation.algorithms.macAlgorithmClientToServer == "hmac-sha2-256")
    #expect(negotiation.algorithms.macAlgorithmServerToClient == "hmac-sha2-512")
}

@Test
func algorithmNegotiatorAllowsOpenSSHChaCha20Poly1305WithoutCommonMAC() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["chacha20-poly1305@openssh.com"],
        encryptionAlgorithmsServerToClient: ["chacha20-poly1305@openssh.com"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-512"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["chacha20-poly1305@openssh.com"],
        encryptionAlgorithmsServerToClient: ["chacha20-poly1305@openssh.com"],
        macAlgorithmsClientToServer: ["umac-64-etm@openssh.com"],
        macAlgorithmsServerToClient: ["umac-128-etm@openssh.com"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )

    #expect(negotiation.algorithms.encryptionAlgorithmClientToServer == "chacha20-poly1305@openssh.com")
    #expect(negotiation.algorithms.encryptionAlgorithmServerToClient == "chacha20-poly1305@openssh.com")
    #expect(negotiation.algorithms.macAlgorithmClientToServer == "hmac-sha2-256")
    #expect(negotiation.algorithms.macAlgorithmServerToClient == "hmac-sha2-512")
}

@Test
func algorithmNegotiatorSelectsClientPreferredAlgorithmsAcrossDirections() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes256-ctr", "aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr", "aes256-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-512", "hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256", "hmac-sha2-512"],
        compressionAlgorithmsClientToServer: ["none", "zlib"],
        compressionAlgorithmsServerToClient: ["none", "zlib"],
        languagesClientToServer: ["en-AU", "en-US"],
        languagesServerToClient: ["fr-FR", "en-US"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["rsa-sha2-512", "ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr", "aes256-ctr"],
        encryptionAlgorithmsServerToClient: ["aes256-ctr", "aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256", "hmac-sha2-512"],
        macAlgorithmsServerToClient: ["hmac-sha2-512", "hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["zlib", "none"],
        compressionAlgorithmsServerToClient: ["none"],
        languagesClientToServer: ["en-US", "ja-JP"],
        languagesServerToClient: ["en-US", "fr-FR"]
    )

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )

    #expect(negotiation.algorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(negotiation.algorithms.serverHostKeyAlgorithm == "ssh-ed25519")
    #expect(negotiation.algorithms.encryptionAlgorithmClientToServer == "aes256-ctr")
    #expect(negotiation.algorithms.encryptionAlgorithmServerToClient == "aes128-ctr")
    #expect(negotiation.algorithms.macAlgorithmClientToServer == "hmac-sha2-512")
    #expect(negotiation.algorithms.macAlgorithmServerToClient == "hmac-sha2-256")
    #expect(negotiation.algorithms.compressionAlgorithmClientToServer == "none")
    #expect(negotiation.algorithms.compressionAlgorithmServerToClient == "none")
    #expect(negotiation.algorithms.languageClientToServer == "en-US")
    #expect(negotiation.algorithms.languageServerToClient == "fr-FR")
    #expect(negotiation.shouldIgnoreNextPacketFromServer == false)
}

@Test
func algorithmNegotiatorTreatsStrictKeyExchangeMarkersAsExtensions() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["kex-strict-c-v00@openssh.com", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["kex-strict-s-v00@openssh.com", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"],
        firstKeyExchangePacketFollows: true
    )

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )

    #expect(negotiation.algorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(negotiation.usesStrictKeyExchange == true)
    #expect(negotiation.shouldIgnoreNextPacketFromServer == false)
}

@Test
func algorithmNegotiatorRejectsMissingCommonAlgorithm() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )

    do {
        _ = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
            localProposal: localProposal,
            remoteProposal: remoteProposal
        )
        Issue.record("Expected no-common-algorithm error")
    } catch {
        #expect(
            error as? SSHAlgorithmNegotiationError
                == .noCommonAlgorithm(.serverHostKey)
        )
    }
}

@Test
func algorithmNegotiatorMarksRemoteWrongGuessWhenFirstPacketFollowsIsSet() throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"],
        firstKeyExchangePacketFollows: true
    )

    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )

    #expect(negotiation.algorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(negotiation.shouldIgnoreNextPacketFromServer == true)
}
