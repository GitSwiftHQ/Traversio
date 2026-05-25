// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func transportProtocolClientConfigurationAppliesCompressionAndServerHostKeyOverrides() {
    let configuration = SSHTransportProtocolClientConfiguration(
        preferredServerHostKeyAlgorithms: ["rsa-sha2-512", "ssh-rsa"],
        compressionPreference: .delayedZlib,
        automaticRekeyPolicy: .disabled,
        keepalivePolicy: .disabled,
        responseTimeoutNanoseconds: 42
    )

    #expect(
        configuration.keyExchangePreferences.serverHostKeyAlgorithms == ["rsa-sha2-512", "ssh-rsa"]
    )
    #expect(
        configuration.keyExchangePreferences.compressionAlgorithmsClientToServer
            == ["zlib@openssh.com", "none"]
    )
    #expect(
        configuration.keyExchangePreferences.compressionAlgorithmsServerToClient
            == ["zlib@openssh.com", "none"]
    )
    #expect(configuration.automaticRekeyPolicy == .disabled)
    #expect(configuration.keepalivePolicy == .disabled)
    #expect(configuration.responseTimeoutNanoseconds == 42)
}

@Test
func transportProtocolClientConfigurationKeepsDefaultHostKeyAlgorithmsForEmptyOverride() {
    let configuration = SSHTransportProtocolClientConfiguration(
        preferredServerHostKeyAlgorithms: [],
        compressionPreference: .disabled
    )

    #expect(
        configuration.keyExchangePreferences.serverHostKeyAlgorithms
            == SSHClientKeyExchangePreferences.default.serverHostKeyAlgorithms
    )
    #expect(
        configuration.keyExchangePreferences.compressionAlgorithmsClientToServer == ["none"]
    )
    #expect(
        configuration.keyExchangePreferences.compressionAlgorithmsServerToClient == ["none"]
    )
}
