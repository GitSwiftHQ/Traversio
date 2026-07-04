// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

// A completed rekey cancels the keepalive and idle-rekey timer tasks at entry. On an
// otherwise idle connection no later protected packet will ever re-arm them (the NEWKEYS
// activity note runs while the rekey flag is still set, so its refresh is a no-op), so the
// rekey exit itself must re-arm both timers — otherwise the first rekey silently disables
// silent-peer detection and periodic idle rekey for the rest of the connection.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRearmsKeepaliveAndIdleRekeyTimersAfterCompletedRekey() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true,
        encryptionAlgorithm: "chacha20-poly1305@openssh.com"
    )
    // Hour-long intervals: the timers must exist but never fire during the test.
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: 3_600_000_000_000
        ),
        keepalivePolicy: SSHTransportKeepalivePolicy(
            intervalNanoseconds: 3_600_000_000_000,
            responseTimeoutNanoseconds: 3_600_000_000_000
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    _ = try await client.authenticatePassword(username: "root", password: "s3cr3t")

    #expect(await client.keepaliveTaskHandle != nil)
    #expect(await client.idleRekeyTaskHandle != nil)

    // Force a rekey from a foreground send (not the keepalive task): the rekey entry
    // cancels both timers.
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
    await client.primeEncryptedPacketCountsSinceLastKeyExchange(outbound: ceiling, inbound: 0)
    try await client.prepareProtectedSend()

    let rekeyMetrics = try #require(
        await waitForCompletedLocalRekeyMetrics(on: client)
    )
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)

    // The connection is idle after the rekey; only the rekey exit can have re-armed these.
    #expect(await client.keepaliveTaskHandle != nil)
    #expect(await client.idleRekeyTaskHandle != nil)

    await client.cancelKeepaliveTask()
    await client.cancelIdleRekeyTask()
}

// A rekey can be initiated from inside the keepalive task itself: here its own global
// request send reaches the chacha sequence-number ceiling. The rekey entry must not cancel
// the task that is performing the rekey — the pre-fix self-cancel aborted the key exchange
// mid-handshake and silently killed the keepalive loop.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCompletesRekeyDrivenByKeepaliveTaskWithoutCancellingItself() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true,
        encryptionAlgorithm: "chacha20-poly1305@openssh.com"
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: .disabled,
        keepalivePolicy: SSHTransportKeepalivePolicy(
            intervalNanoseconds: UInt64(backgroundKeepaliveTestInterval * 1_000_000_000),
            responseTimeoutNanoseconds: 2_000_000_000
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    _ = try await client.authenticatePassword(username: "root", password: "s3cr3t")

    // The connection stays idle, so the next protected send is the keepalive's own global
    // request: the forced ceiling rekey runs on the keepalive timer task.
    let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
    await client.primeEncryptedPacketCountsSinceLastKeyExchange(outbound: ceiling, inbound: 0)

    let rekeyMetrics = try #require(
        await waitForCompletedLocalRekeyMetrics(on: client)
    )
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
    // The keepalive loop survived driving its own rekey.
    #expect(await client.keepaliveTaskHandle != nil)
    #expect(await client.pendingBackgroundTransportFailure == nil)

    await client.cancelKeepaliveTask()
    await client.cancelIdleRekeyTask()
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForCompletedLocalRekeyMetrics(
    on client: SSHTransportProtocolClient,
    maxAttempts: Int = 400
) async -> SSHTransportProtocolRekeyMetricsSnapshot? {
    for _ in 0..<maxAttempts {
        let metrics = await client.rekeyMetricsSnapshot()
        if metrics.completedLocalRekeyCount == 1,
           !metrics.isTransportRekeyInProgress {
            return metrics
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}
