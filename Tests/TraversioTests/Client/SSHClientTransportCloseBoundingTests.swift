// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Suite("Transport close bounding")
struct SSHClientTransportCloseBoundingTests {
    @Test(.timeLimit(.minutes(1)))
    func closeTransportResourcesReturnsWithinBoundWhenTransportHandleCloseStalls() async {
        let client = SSHTransportProtocolClient(
            transport: ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
        )
        let stall = TransportCloseStallGate()
        let handle = SSHClientTransportHandle(
            transport: ProtocolClientMockSSHByteStreamTransport(receiveChunks: []),
            closeOperation: {
                // Simulate a modern route-root close whose structured scope never
                // drops (e.g. a future OS blocking scope exit on an in-flight
                // receive).
                await stall.wait()
            }
        )
        let logRecorder = TransportCloseLogRecorder()
        let logHandler = SSHClientLogHandler.sink(minimumLevel: .debug) { event in
            logRecorder.record(event)
        }
        let gracefulCloseTimeoutNanoseconds: UInt64 = 100_000_000

        let startedAt = DispatchTime.now().uptimeNanoseconds
        await SSHClient.closeTransportResources(
            client: client,
            transportHandle: handle,
            dependentCloseOperation: nil,
            gracefulCloseTimeoutNanoseconds: gracefulCloseTimeoutNanoseconds,
            logHandler: logHandler
        )
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startedAt

        #expect(elapsedNanoseconds < gracefulCloseTimeoutNanoseconds * 30)
        let timeoutEvents = logRecorder.recorded().filter { event in
            event.category == .transport
                && event.message.contains("Timed out closing transport handle")
        }
        #expect(timeoutEvents.count == 1)
        #expect(timeoutEvents.first?.level == .warning)

        // Release the stall so the background close finishes and nothing leaks.
        stall.release()
    }

    @Test(.timeLimit(.minutes(1)))
    func sshConnectionCloseIsBoundedWithKeepaliveDisabledAgainstSilentPeer() async throws {
        let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
        let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
            .success(SSHUserAuthenticationSuccessMessage())
        )
        let transport = ConnectionFixtureMockSSHByteStreamTransport(
            serverPayloadsAfterNewKeys: [
                serviceAcceptPayload,
                authSuccessPayload,
            ],
            // Stay connected but silent after authentication: the peer never
            // sends another byte and never closes.
            emptyReceiveBehavior: .waitForAppendedChunks
        )
        let stall = TransportCloseStallGate()
        let configuration = SSHClientConfiguration(
            host: "example.com",
            username: "root",
            authentication: .password("s3cr3t"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey,
            keepalivePolicy: .disabled,
            timeoutPolicy: SSHTimeoutPolicy(responseTimeInterval: 0.2)
        )

        let connection = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                SSHClientTransportHandle(
                    transport: transport,
                    closeOperation: {
                        // Simulate a stuck route-root scope drop during close.
                        await stall.wait()
                    }
                )
            }
        )

        let startedAt = DispatchTime.now().uptimeNanoseconds
        await connection.close()
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startedAt

        // With keepalive disabled and a silent peer, close must still return
        // bounded: the disconnect and the stalled handle close are both capped.
        #expect(elapsedNanoseconds < 5_000_000_000)

        stall.release()
    }
}

private final class TransportCloseStallGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isReleased = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            self.lock.lock()
            if self.isReleased {
                self.lock.unlock()
                continuation.resume()
                return
            }
            self.waiters.append(continuation)
            self.lock.unlock()
        }
    }

    func release() {
        self.lock.lock()
        guard !self.isReleased else {
            self.lock.unlock()
            return
        }
        self.isReleased = true
        let waiters = self.waiters
        self.waiters.removeAll(keepingCapacity: false)
        self.lock.unlock()

        for waiter in waiters {
            waiter.resume()
        }
    }
}

private final class TransportCloseLogRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [SSHClientLogEvent] = []

    func record(_ event: SSHClientLogEvent) {
        self.lock.lock()
        self.events.append(event)
        self.lock.unlock()
    }

    func recorded() -> [SSHClientLogEvent] {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.events
    }
}
