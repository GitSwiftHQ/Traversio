// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

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
