// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing

actor RouteSetupTimeoutRecorder {
    private var cancellationCount = 0
    private var completionCount = 0

    func recordCancellation() {
        self.cancellationCount += 1
    }

    func recordCompletion() {
        self.completionCount += 1
    }

    func cancellationCountObserved() -> Int {
        self.cancellationCount
    }

    func completionCountObserved() -> Int {
        self.completionCount
    }
}

private actor RouteSetupTimeoutCancellationWaiter {
    private let recorder: RouteSetupTimeoutRecorder
    private var continuation: CheckedContinuation<Void, any Error>?
    private var hasRecordedCancellation = false

    init(recording recorder: RouteSetupTimeoutRecorder) {
        self.recorder = recorder
    }

    func wait() async throws {
        if Task.isCancelled {
            await self.cancel()
            throw CancellationError()
        }

        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            if self.hasRecordedCancellation {
                continuation.resume(throwing: CancellationError())
            } else {
                self.continuation = continuation
            }
        }
    }

    func cancel() async {
        guard !self.hasRecordedCancellation else {
            return
        }

        self.hasRecordedCancellation = true
        await self.recorder.recordCancellation()
        self.continuation?.resume(throwing: CancellationError())
        self.continuation = nil
    }
}

func suspendUntilRouteSetupTimeoutCancellation(
    recording recorder: RouteSetupTimeoutRecorder
) async throws {
    let waiter = RouteSetupTimeoutCancellationWaiter(recording: recorder)
    try await withTaskCancellationHandler {
        try await waiter.wait()
    } onCancel: {
        Task {
            await waiter.cancel()
        }
    }
    await recorder.recordCompletion()
}
