// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Suite("Structured route-root transport owner")
struct SSHStructuredRouteRootTransportHandleOwnerTests {
    @Test(.timeLimit(.minutes(1)))
    func ownerPublishesHandleAndReleasesScopeOnClose() async throws {
        let log = RouteRootOwnerTestLog()
        let transport = RouteRootOwnerTestTransport(log: log)
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport> {
            handler in
            await log.record(.runnerEntered)
            try await handler(transport)
            await log.record(.runnerExited)
        }

        let handle = try await owner.makeHandle()

        #expect(await log.hasRecorded(.runnerEntered))
        #expect(!(await log.hasRecorded(.runnerExited)))

        await handle.close()

        #expect(
            await log.events() == [
                .runnerEntered,
                .transportClosed,
                .runnerExited
            ]
        )
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerReleasesScopeOnAbort() async throws {
        let log = RouteRootOwnerTestLog()
        let transport = RouteRootOwnerTestTransport(log: log)
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport> {
            handler in
            await log.record(.runnerEntered)
            try await handler(transport)
            await log.record(.runnerExited)
        }

        let handle = try await owner.makeHandle()
        await handle.abort()

        #expect(
            await log.events() == [
                .runnerEntered,
                .transportAborted,
                .runnerExited
            ]
        )
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerDoesNotCancelRunnerWhenPublishedHandleAborts() async throws {
        let log = RouteRootOwnerTestLog()
        let transport = RouteRootOwnerTestTransport(log: log)
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport> {
            handler in
            await log.record(.runnerEntered)
            try await handler(transport)
            do {
                try await Task.sleep(nanoseconds: 10_000_000)
            } catch {
                await log.record(.runnerCancelled)
            }
            await log.record(.runnerExited)
        }

        let handle = try await owner.makeHandle()
        await handle.abort()

        #expect(
            await log.events() == [
                .runnerEntered,
                .transportAborted,
                .runnerExited
            ]
        )
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerCancelsRunnerWhenHandleAcquisitionIsCancelled() async throws {
        let log = RouteRootOwnerTestLog()
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport> {
            _ in
            await log.record(.runnerEntered)
            do {
                try await Task.sleep(nanoseconds: 60_000_000_000)
            } catch {
                await log.record(.runnerCancelled)
                throw error
            }
        }

        let task = Task {
            try await owner.makeHandle()
        }

        await log.waitFor(.runnerEntered)
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected cancelled handle acquisition to throw")
        } catch {
            #expect(error is CancellationError)
        }

        await log.waitFor(.runnerCancelled)
        #expect(await log.events() == [.runnerEntered, .runnerCancelled])
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerCloseReturnsWithinBoundWhenRunnerTeardownStalls() async throws {
        let stall = RouteRootOwnerManualGate()
        let diagnostics = RouteRootOwnerDiagnosticsRecorder()
        let transport = RouteRootOwnerTestTransport(log: RouteRootOwnerTestLog())
        let timeoutNanoseconds: UInt64 = 50_000_000
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport>(
            teardownTimeoutNanoseconds: timeoutNanoseconds,
            teardownDiagnosticHandler: { diagnostic in
                diagnostics.record(diagnostic)
            }
        ) { handler in
            try await handler(transport)
            // Simulate a scope exit that blocks on an in-flight receive: the
            // runner never returns until the test releases the gate.
            await stall.wait()
        }

        let handle = try await owner.makeHandle()

        let startedAt = DispatchTime.now().uptimeNanoseconds
        await handle.close()
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startedAt

        // Bounded wall-clock: the close must return shortly after the backstop
        // window, not wait for the stuck runner.
        #expect(elapsedNanoseconds < timeoutNanoseconds * 20)
        #expect(
            diagnostics.recorded() == [
                SSHStructuredRouteRootOwnerTeardownDiagnostic(
                    operation: .close,
                    timeoutNanoseconds: timeoutNanoseconds
                )
            ]
        )

        // Release the stall so the runner exits and nothing leaks.
        stall.release()
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerAbortReportsTeardownTimeoutDiagnostic() async throws {
        let stall = RouteRootOwnerManualGate()
        let diagnostics = RouteRootOwnerDiagnosticsRecorder()
        let transport = RouteRootOwnerTestTransport(log: RouteRootOwnerTestLog())
        let timeoutNanoseconds: UInt64 = 50_000_000
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport>(
            teardownTimeoutNanoseconds: timeoutNanoseconds,
            teardownDiagnosticHandler: { diagnostic in
                diagnostics.record(diagnostic)
            }
        ) { handler in
            try await handler(transport)
            await stall.wait()
        }

        let handle = try await owner.makeHandle()
        await handle.abort()

        #expect(
            diagnostics.recorded() == [
                SSHStructuredRouteRootOwnerTeardownDiagnostic(
                    operation: .abort,
                    timeoutNanoseconds: timeoutNanoseconds
                )
            ]
        )

        stall.release()
    }

    @Test(.timeLimit(.minutes(1)))
    func ownerPropagatesRunnerFailureBeforeTransportPublication() async {
        let owner = SSHStructuredRouteRootTransportHandleOwner<RouteRootOwnerTestTransport> {
            _ in
            throw SSHTransportError.transportClosed
        }

        do {
            _ = try await owner.makeHandle()
            Issue.record("Expected owner setup to throw the runner failure")
        } catch {
            #expect(error as? SSHTransportError == .transportClosed)
        }
    }
}

private final class RouteRootOwnerTestTransport: SSHByteStreamTransport, @unchecked Sendable {
    private let log: RouteRootOwnerTestLog

    init(log: RouteRootOwnerTestLog) {
        self.log = log
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        throw SSHTransportError.transportClosed
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        throw SSHTransportError.transportClosed
    }

    func close() async {
        await self.log.record(.transportClosed)
    }

    func abort() async {
        await self.log.record(.transportAborted)
    }
}

private final class RouteRootOwnerDiagnosticsRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [SSHStructuredRouteRootOwnerTeardownDiagnostic] = []

    func record(_ diagnostic: SSHStructuredRouteRootOwnerTeardownDiagnostic) {
        self.lock.lock()
        self.events.append(diagnostic)
        self.lock.unlock()
    }

    func recorded() -> [SSHStructuredRouteRootOwnerTeardownDiagnostic] {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.events
    }
}

private final class RouteRootOwnerManualGate: @unchecked Sendable {
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

private actor RouteRootOwnerTestLog {
    enum Event: Equatable, Hashable, Sendable {
        case runnerEntered
        case runnerExited
        case runnerCancelled
        case transportClosed
        case transportAborted
    }

    private var recordedEvents: [Event] = []
    private var waiters: [Event: [CheckedContinuation<Void, Never>]] = [:]

    func record(_ event: Event) {
        self.recordedEvents.append(event)
        let continuations = self.waiters.removeValue(forKey: event) ?? []
        for continuation in continuations {
            continuation.resume()
        }
    }

    func events() -> [Event] {
        self.recordedEvents
    }

    func hasRecorded(_ event: Event) -> Bool {
        self.recordedEvents.contains(event)
    }

    func waitFor(_ event: Event) async {
        if self.recordedEvents.contains(event) {
            return
        }

        await withCheckedContinuation { continuation in
            self.waiters[event, default: []].append(continuation)
        }
    }
}
