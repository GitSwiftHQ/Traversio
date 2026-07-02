// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

// MARK: - Fix A: chacha20-poly1305 sequence-number-nonce rekey ceiling

@Test
func sequenceNumberNonceRekeyCeilingSitsSafelyBelowThirtyTwoBitWrap() {
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
    // The sequence counters are UInt32 and wrap at 2^32; the ceiling must force a rekey well
    // before then. We pin it at exactly half the wrap point (a 2^31-packet safety margin).
    #expect(ceiling == 1 << 31)
    #expect(ceiling < UInt64(UInt32.max))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReportsCeilingTriggerOnlyForChaChaPolyAtOrAboveCeiling() async throws {
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [],
        encryptionAlgorithm: "chacha20-poly1305@openssh.com"
    )
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling

    // Just below the ceiling in both directions: no forced rekey yet.
    await fixture.client.primeEncryptedPacketCountsSinceLastKeyExchange(
        outbound: ceiling - 1,
        inbound: ceiling - 1
    )
    #expect(await fixture.client.mandatorySequenceNumberCeilingTrigger() == nil)

    // At the ceiling on the inbound side: the trigger fires even though the configured policy is
    // the default (its packet thresholds are far higher and would never notice a UInt32 wrap).
    await fixture.client.primeEncryptedPacketCountsSinceLastKeyExchange(
        outbound: 0,
        inbound: ceiling
    )
    #expect(
        await fixture.client.mandatorySequenceNumberCeilingTrigger()
            == .mandatorySequenceNumberCeiling(currentCount: ceiling, ceiling: ceiling)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientIgnoresCeilingForNonSequenceNumberNonceCipher() async throws {
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [],
        encryptionAlgorithm: "aes128-ctr"
    )
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling

    await fixture.client.primeEncryptedPacketCountsSinceLastKeyExchange(
        outbound: ceiling,
        inbound: ceiling
    )

    // aes128-ctr keeps a continuous cipher state, so a wrapping sequence number does not repeat a
    // keystream: no forced rekey and no fail-closed.
    #expect(await fixture.client.mandatorySequenceNumberCeilingTrigger() == nil)
    try await fixture.client.prepareProtectedSend()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientForcesRekeyAtChaChaCeilingEvenWhenPolicyDisabled() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true,
        encryptionAlgorithm: "chacha20-poly1305@openssh.com"
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: .disabled
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    // The rekey policy is `.disabled`, so ordinary traffic would never rekey. Drive the outbound
    // counter to the hard ceiling; the very next protected send must force a key re-exchange
    // rather than let the 32-bit sequence number wrap and reuse a nonce.
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
    await client.primeEncryptedPacketCountsSinceLastKeyExchange(outbound: ceiling, inbound: 0)

    try await client.prepareProtectedSend()

    let rekeyClientProposal = try #require(
        await waitForCeilingRekeyClientProposal(on: transport)
    )
    let rekeyMetrics = try #require(
        await waitForCeilingCompletedLocalRekeyMetrics(on: client)
    )

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
    #expect(rekeyMetrics.completedRemoteRekeyCount == 0)
    // The rekey resets the per-key packet counters, moving the connection back well below the
    // ceiling before any nonce could repeat.
    #expect(rekeyMetrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0)
    #expect(rekeyMetrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0)
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientFailsClosedAtChaChaCeilingWhenUnableToRekey() async throws {
    // Activated but not yet authenticated: OpenSSH forbids a client-initiated KEXINIT during
    // ssh-userauth, so no rekey is possible. Reaching the ceiling here must fail the connection
    // closed rather than protect another packet under a soon-to-wrap nonce.
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [],
        encryptionAlgorithm: "chacha20-poly1305@openssh.com"
    )
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
    await fixture.client.primeEncryptedPacketCountsSinceLastKeyExchange(
        outbound: ceiling,
        inbound: 0
    )

    await #expect(
        throws: SSHTransportSequenceNumberNonceError.ceilingReachedWithoutRekey(
            currentCount: ceiling,
            ceiling: ceiling
        )
    ) {
        try await fixture.client.prepareProtectedSend()
    }
}

// MARK: - Fix B: timer de-churn

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReusesTimersInsteadOfSpawningOnePerProtectedActivity() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    // Long intervals so neither timer actually fires during the test; we are measuring scheduling
    // churn, not firing behavior.
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks,
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: 10_000_000_000
        ),
        keepalivePolicy: SSHTransportKeepalivePolicy(
            intervalNanoseconds: 10_000_000_000,
            responseTimeoutNanoseconds: 10_000_000_000
        )
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    // Exactly one long-lived timer per concern should have been scheduled at authentication.
    let baselineKeepaliveSchedules = await fixture.client.keepaliveTimerScheduleCount
    let baselineIdleRekeySchedules = await fixture.client.idleRekeyTimerScheduleCount
    #expect(baselineKeepaliveSchedules == 1)
    #expect(baselineIdleRekeySchedules == 1)

    for _ in 0..<1_000 {
        await fixture.client.noteProtectedTransportActivity()
    }

    // The hot path must not spawn a fresh timer task per packet: both counters stay put.
    #expect(await fixture.client.keepaliveTimerScheduleCount == baselineKeepaliveSchedules)
    #expect(await fixture.client.idleRekeyTimerScheduleCount == baselineIdleRekeySchedules)

    await fixture.client.cancelKeepaliveTask()
    await fixture.client.cancelIdleRekeyTask()
}

// MARK: - Local wait helpers

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForCeilingRekeyClientProposal(
    on transport: ServiceRequestRekeyMockSSHByteStreamTransport,
    maxAttempts: Int = 200
) async -> SSHKeyExchangeInitMessage? {
    for _ in 0..<maxAttempts {
        if let proposal = await transport.rekeyClientProposal() {
            return proposal
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForCeilingCompletedLocalRekeyMetrics(
    on client: SSHTransportProtocolClient,
    maxAttempts: Int = 200
) async -> SSHTransportProtocolRekeyMetricsSnapshot? {
    for _ in 0..<maxAttempts {
        let metrics = await client.rekeyMetricsSnapshot()
        if metrics.completedLocalRekeyCount == 1,
           metrics.completedRemoteRekeyCount == 0,
           metrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0,
           metrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0,
           !metrics.isTransportRekeyInProgress {
            return metrics
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}
