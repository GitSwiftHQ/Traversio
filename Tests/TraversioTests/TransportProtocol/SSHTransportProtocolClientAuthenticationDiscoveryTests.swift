// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDiscoversAuthenticationMethodsWithNoneRequest() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Authorized use only",
                languageTag: "en-US"
            )
        )
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["publickey", "password"],
                partialSuccess: false
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            failurePayload,
        ]
    )

    let result = try await fixture.client.discoverAuthenticationMethods(username: "root")

    #expect(
        result
            == SSHAuthenticationMethodDiscoveryResult(
                username: "root",
                serviceName: "ssh-connection",
                availableMethods: ["publickey", "password"],
                partialSuccess: false,
                allowsUnauthenticatedAccess: false,
                banners: [
                    SSHAuthenticationBanner(
                        message: "Authorized use only",
                        languageTag: "en-US"
                    )
                ]
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let discoveryRequestPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 4)
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(discoveryRequestPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .none
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDiscoveryReportsUnauthenticatedAccess() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.discoverAuthenticationMethods(username: "root")

    #expect(
        result
            == SSHAuthenticationMethodDiscoveryResult(
                username: "root",
                serviceName: "ssh-connection",
                availableMethods: [],
                partialSuccess: false,
                allowsUnauthenticatedAccess: true,
                banners: []
            )
    )
}
