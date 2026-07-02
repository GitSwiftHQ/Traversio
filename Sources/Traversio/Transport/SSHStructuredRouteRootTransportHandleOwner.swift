// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

final class SSHStructuredRouteRootTransportHandleOwner<
    Transport: SSHByteStreamTransport
>: @unchecked Sendable {
    typealias Runner = @Sendable (
        _ handler: @escaping @Sendable (Transport) async throws -> Void
    ) async throws -> Void
    typealias TeardownDiagnosticHandler = @Sendable (
        SSHStructuredRouteRootOwnerTeardownDiagnostic
    ) -> Void

    // Deterministic close of a modern `NetworkConnection<TCP>` (Apple 26+, which
    // exposes no cancel/close API) relies on the runner's `withNetworkConnection`
    // scope tearing the connection down on exit. `close()`/`abort()` therefore
    // wait for the runner task to finish. If a future OS were to block that scope
    // exit on an in-flight receive rather than failing it (e.g. with POSIX 89),
    // that wait would hang forever. This bounded backstop caps the wait: once the
    // timeout elapses we record a diagnostic and return, letting the scope keep
    // draining in the background instead of wedging the caller. We deliberately
    // do NOT cancel the runner on a published handle (see 1.0.6) — cancelling
    // could strand an escaped connection. Acquisition-time cancellation still
    // cancels the runner via `cancelFromSynchronousContext`. The default is
    // intentionally looser than `SSHClient`'s graceful-close bound, which is the
    // fast production backstop; this only guards direct owner users.
    static var defaultTeardownTimeoutNanoseconds: UInt64 { 5_000_000_000 }

    private let runner: Runner
    private let teardownTimeoutNanoseconds: UInt64
    private let teardownDiagnosticHandler: TeardownDiagnosticHandler?
    private let readyTransport = SSHTCPAsyncResult<Transport>()
    private let scopeGate = SSHStructuredRouteRootScopeGate()
    private let taskBox = SSHStructuredRouteRootOwnerTaskBox()

    init(
        teardownTimeoutNanoseconds: UInt64 =
            SSHStructuredRouteRootTransportHandleOwner.defaultTeardownTimeoutNanoseconds,
        teardownDiagnosticHandler: TeardownDiagnosticHandler? = nil,
        runner: @escaping Runner
    ) {
        self.runner = runner
        self.teardownTimeoutNanoseconds = teardownTimeoutNanoseconds
        self.teardownDiagnosticHandler = teardownDiagnosticHandler
    }

    deinit {
        self.cancelFromSynchronousContext()
    }

    func makeHandle() async throws -> SSHClientTransportHandle {
        let readyTransport = self.readyTransport
        let scopeGate = self.scopeGate
        let runner = self.runner
        let ownerTask = Task {
            do {
                try await runner { transport in
                    readyTransport.resume(with: .success(transport))
                    await scopeGate.waitUntilClosed()
                }

                readyTransport.resume(with: .failure(CancellationError()))
            } catch {
                readyTransport.resume(with: .failure(error))
            }
        }
        self.taskBox.install(ownerTask)

        do {
            let transport = try await withTaskCancellationHandler {
                try await self.readyTransport.value()
            } onCancel: {
                self.cancelFromSynchronousContext()
            }

            return SSHClientTransportHandle(
                transport: transport,
                closeOperation: { [self] in
                    await self.close()
                },
                abortOperation: { [self] in
                    await self.abort()
                }
            )
        } catch {
            await self.abort()
            throw error
        }
    }

    func close() async {
        self.scopeGate.close()
        await self.waitForRunnerTeardown(operation: .close)
    }

    func abort() async {
        self.scopeGate.close()
        await self.waitForRunnerTeardown(operation: .abort)
    }

    private func waitForRunnerTeardown(
        operation: SSHStructuredRouteRootOwnerTeardownDiagnostic.Operation
    ) async {
        let didFinish = await self.taskBox.waitUntilFinished(
            upTo: self.teardownTimeoutNanoseconds
        )
        guard !didFinish else {
            return
        }

        // The runner did not exit within the backstop window. We deliberately do
        // not cancel it (that could strand an escaped connection on a published
        // handle); the structured scope keeps draining in the background while we
        // return so the caller's teardown is not wedged.
        self.teardownDiagnosticHandler?(
            SSHStructuredRouteRootOwnerTeardownDiagnostic(
                operation: operation,
                timeoutNanoseconds: self.teardownTimeoutNanoseconds
            )
        )
    }

    private func cancelFromSynchronousContext() {
        self.scopeGate.close()
        self.taskBox.cancel()
    }
}

struct SSHStructuredRouteRootOwnerTeardownDiagnostic: Sendable, Equatable {
    enum Operation: String, Sendable {
        case close
        case abort
    }

    let operation: Operation
    let timeoutNanoseconds: UInt64
}

private final class SSHStructuredRouteRootScopeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isClosed = false
    private var waiters: [UInt64: CheckedContinuation<Void, Never>] = [:]
    private var cancelledWaiterIDs: Set<UInt64> = []
    private var nextWaiterID: UInt64 = 0

    func waitUntilClosed() async {
        let waiterID = self.allocateWaiterID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.install(continuation, waiterID: waiterID)
            }
        } onCancel: {
            self.cancelWaiter(waiterID)
        }
    }

    func close() {
        let waiters: [CheckedContinuation<Void, Never>]

        self.lock.lock()
        guard !self.isClosed else {
            self.lock.unlock()
            return
        }

        self.isClosed = true
        waiters = Array(self.waiters.values)
        self.waiters.removeAll(keepingCapacity: false)
        self.cancelledWaiterIDs.removeAll(keepingCapacity: false)
        self.lock.unlock()

        for waiter in waiters {
            waiter.resume()
        }
    }

    private func allocateWaiterID() -> UInt64 {
        self.lock.lock()
        defer { self.lock.unlock() }

        let waiterID = self.nextWaiterID
        self.nextWaiterID &+= 1
        return waiterID
    }

    private func install(
        _ continuation: CheckedContinuation<Void, Never>,
        waiterID: UInt64
    ) {
        let shouldResume: Bool

        self.lock.lock()
        if self.isClosed {
            shouldResume = true
        } else if self.cancelledWaiterIDs.remove(waiterID) != nil {
            shouldResume = true
        } else {
            precondition(
                self.waiters[waiterID] == nil,
                "structured route-root scope gate already has this waiter"
            )
            self.waiters[waiterID] = continuation
            shouldResume = false
        }
        self.lock.unlock()

        if shouldResume {
            continuation.resume()
        }
    }

    private func cancelWaiter(_ waiterID: UInt64) {
        let continuation: CheckedContinuation<Void, Never>?

        self.lock.lock()
        if self.isClosed {
            continuation = nil
        } else if let waiter = self.waiters.removeValue(forKey: waiterID) {
            continuation = waiter
        } else {
            self.cancelledWaiterIDs.insert(waiterID)
            continuation = nil
        }
        self.lock.unlock()

        continuation?.resume()
    }
}

private final class SSHStructuredRouteRootOwnerTaskBox: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Never>?

    func install(_ task: Task<Void, Never>) {
        self.lock.lock()
        precondition(self.task == nil, "structured route-root owner task installed twice")
        self.task = task
        self.lock.unlock()
    }

    func cancel() {
        self.taskSnapshot()?.cancel()
    }

    /// Waits for the owner task to finish, giving up after `nanoseconds`.
    ///
    /// Returns `true` if the task finished within the budget and `false` if the
    /// wait timed out (the task is left running).
    func waitUntilFinished(upTo nanoseconds: UInt64) async -> Bool {
        guard let task = self.taskSnapshot() else {
            return true
        }

        return await withCheckedContinuation { continuation in
            let gate = SSHStructuredRouteRootOwnerCompletionGate(continuation)

            Task {
                await task.value
                await gate.resume(with: true)
            }

            Task {
                try? await Task.sleep(nanoseconds: nanoseconds)
                await gate.resume(with: false)
            }
        }
    }

    private func taskSnapshot() -> Task<Void, Never>? {
        self.lock.lock()
        defer { self.lock.unlock() }

        return self.task
    }
}

private actor SSHStructuredRouteRootOwnerCompletionGate {
    private var continuation: CheckedContinuation<Bool, Never>?

    init(_ continuation: CheckedContinuation<Bool, Never>) {
        self.continuation = continuation
    }

    func resume(with value: Bool) {
        guard let continuation = self.continuation else {
            return
        }

        self.continuation = nil
        continuation.resume(returning: value)
    }
}
