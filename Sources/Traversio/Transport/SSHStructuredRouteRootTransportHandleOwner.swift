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

    private let runner: Runner
    private let readyTransport = SSHTCPAsyncResult<Transport>()
    private let scopeGate = SSHStructuredRouteRootScopeGate()
    private let taskBox = SSHStructuredRouteRootOwnerTaskBox()

    init(runner: @escaping Runner) {
        self.runner = runner
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
        await self.taskBox.waitUntilFinished()
    }

    func abort() async {
        self.scopeGate.close()
        self.taskBox.cancel()
        await self.taskBox.waitUntilFinished()
    }

    private func cancelFromSynchronousContext() {
        self.scopeGate.close()
        self.taskBox.cancel()
    }
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

    func waitUntilFinished() async {
        await self.taskSnapshot()?.value
    }

    private func taskSnapshot() -> Task<Void, Never>? {
        self.lock.lock()
        defer { self.lock.unlock() }

        return self.task
    }
}
