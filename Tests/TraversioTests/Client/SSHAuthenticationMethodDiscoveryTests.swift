// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Test
func sshClientDiscoversAuthenticationMethodsThroughPublicAPI() async throws {
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
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            failurePayload,
        ]
    )
    let configuration = SSHAuthenticationMethodDiscoveryConfiguration(
        host: "example.com",
        username: "root",
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let result = try await SSHClient.discoverAuthenticationMethods(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    )

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
    #expect(await transport.closeCountObserved() == 1)
}

@Test
func sshClientDiscoveryReportsUnauthenticatedAccessThroughPublicAPI() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            successPayload,
        ]
    )
    let configuration = SSHAuthenticationMethodDiscoveryConfiguration(
        host: "example.com",
        username: "root",
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let result = try await SSHClient.discoverAuthenticationMethods(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    )

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
    #expect(await transport.closeCountObserved() == 1)
}

@Test
func sshClientAuthenticationDiscoveryProxyJumpFirstHopRouteSetupTimeoutUsesHopPolicy()
    async throws {
    let configuration = SSHAuthenticationMethodDiscoveryConfiguration(
        host: "db.internal",
        username: "root",
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey,
                timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05)
            )
        ]
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()

    do {
        _ = try await SSHClient.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
                return SSHClientTransportHandle(
                    transport: try makeAuthenticatedDiscoveryHopTransport()
                )
            },
            jumpTransportFactory: { _, _ in
                Issue.record("Final ProxyJump discovery route should not open after first-hop timeout")
                return SSHClientTransportHandle(
                    transport: try makeAuthenticationDiscoveryFailureTransport()
                )
            }
        )
        Issue.record("Expected first ProxyJump discovery hop route setup to time out")
    } catch {
        let failure = try #require(authenticationDiscoveryConnectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.stage == .identification)
        #expect(failure.diagnostics.endpointHost == "jump-1.example.com")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
}

@Test
func sshClientAuthenticationDiscoveryProxyJumpFinalRouteSetupTimeoutClosesHops() async throws {
    let firstHopTransport = try makeAuthenticatedDiscoveryHopTransport()
    let configuration = SSHAuthenticationMethodDiscoveryConfiguration(
        host: "db.internal",
        username: "root",
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()

    do {
        _ = try await SSHClient.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                SSHClientTransportHandle(transport: firstHopTransport)
            },
            jumpTransportFactory: { _, endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
                try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
                return SSHClientTransportHandle(
                    transport: try makeAuthenticationDiscoveryFailureTransport()
                )
            }
        )
        Issue.record("Expected final ProxyJump discovery route setup to time out")
    } catch {
        let failure = try #require(authenticationDiscoveryConnectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.stage == .identification)
        #expect(failure.diagnostics.endpointHost == "db.internal")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await firstHopTransport.closeCountObserved() == 1)
}

private func authenticationDiscoveryConnectionFailure(from error: any Error)
    -> SSHConnectionFailure? {
    guard case let .connectionFailed(failure)? = error as? SSHClientError else {
        return nil
    }

    return failure
}

private func makeAuthenticatedDiscoveryHopTransport() throws
    -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
}

private func makeAuthenticationDiscoveryFailureTransport() throws
    -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["publickey", "password"],
                partialSuccess: false
            )
        )
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            failurePayload,
        ]
    )
}
