// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Immutable snapshot of a bounded `SSHClientLogRecorder`.
public struct SSHClientLogRecorderSnapshot: Sendable {
    /// Events.
    public let events: [SSHClientLogEvent]
    /// Maximum Event Count.
    public let maximumEventCount: Int
    /// Dropped Event Count.
    public let droppedEventCount: Int

    /// Formatted Lines.
    public var formattedLines: [String] {
        self.events.map(\.formattedLine)
    }

    /// Formatted Text.
    public var formattedText: String {
        var lines: [String] = []
        lines.reserveCapacity(self.events.count + (self.droppedEventCount > 0 ? 1 : 0))

        if self.droppedEventCount > 0 {
            lines.append("dropped-log-events: \(self.droppedEventCount)")
        }

        lines.append(contentsOf: self.formattedLines)
        return lines.joined(separator: "\n")
    }

    /// Builds a redacted diagnostic report from an optional error and the
    /// recorded log lines.
    public func diagnosticReport(for error: Error? = nil) -> String? {
        let logText = self.formattedText.isEmpty ? nil : self.formattedText
        let errorReport: String?

        if let clientError = error as? SSHClientError {
            errorReport = sshClientErrorDiagnosticReport(for: clientError)
        } else {
            errorReport = nil
        }

        switch (errorReport, logText) {
        case let (.some(errorReport), .some(logText)):
            return "\(errorReport)\n\n\(logText)"
        case let (.some(errorReport), .none):
            return errorReport
        case let (.none, .some(logText)):
            return logText
        case (.none, .none):
            return nil
        }
    }
}

private func sshClientErrorDiagnosticReport(for error: SSHClientError) -> String? {
    switch error {
    case let .connectionFailed(failure):
        return failure.diagnosticReport
    case let .operationFailed(failure):
        return failure.diagnosticReport
    case let .authenticationRejected(methodName, availableMethods, partialSuccess, banners):
        var lines = [
            "SSH client error",
            "case: authenticationRejected",
            "message: Authentication method \(methodName) was rejected by the server.",
            "authentication-method: \(methodName)",
            "available-methods: \(availableMethods.isEmpty ? "none" : availableMethods.joined(separator: ","))",
            "partial-success: \(partialSuccess)",
        ]
        appendAuthenticationBanners(banners, to: &lines)
        return lines.joined(separator: "\n")
    case let .passwordChangeRequired(prompt, languageTag, banners):
        let diagnosticLanguageTag = languageTag.isEmpty
            ? "none"
            : sshDiagnosticRedacted(languageTag)
        var lines = [
            "SSH client error",
            "case: passwordChangeRequired",
            "message: Password change is required before authentication can continue.",
            "password-change-prompt: \(sshDiagnosticRedacted(prompt))",
            "password-change-language-tag: \(diagnosticLanguageTag)",
        ]
        appendAuthenticationBanners(banners, to: &lines)
        return lines.joined(separator: "\n")
    case .connectionScopeEnded:
        return [
            "SSH client error",
            "case: connectionScopeEnded",
            "message: The SSH connection scope ended before the requested operation completed.",
        ].joined(separator: "\n")
    }
}

private func appendAuthenticationBanners(
    _ banners: [SSHAuthenticationBanner],
    to lines: inout [String]
) {
    if banners.isEmpty {
        lines.append("authentication-banners: none")
        return
    }

    for (index, banner) in banners.enumerated() {
        let languageTag = banner.languageTag.isEmpty
            ? "none"
            : sshDiagnosticRedacted(banner.languageTag)
        lines.append(
            "authentication-banner[\(index)]: languageTag=\(languageTag) message=\(sshDiagnosticRedacted(banner.message))"
        )
    }
}

/// Bounded in-memory recorder for Traversio client log events.
///
/// Use a recorder when an app wants recent redacted logs after a connection or
/// operation failure.
///
/// Example:
///
/// ```swift
/// let recorder = SSHClientLogRecorder()
/// do {
///     _ = try await SSHClient.connect(
///         configuration: configuration,
///         logHandler: recorder.logHandler(minimumLevel: .debug)
///     )
/// } catch {
///     print(recorder.diagnosticReport(for: error) ?? "")
/// }
/// ```
public final class SSHClientLogRecorder: @unchecked Sendable {
    // Sendable invariant: `events` and `droppedEventCount` are protected by `lock`;
    // `maximumEventCount` is immutable after initialization.
    private let maximumEventCount: Int
    private let lock = NSLock()
    private var events: [SSHClientLogEvent]
    private var droppedEventCount: Int

    /// Creates a value.
    public init(maximumEventCount: Int = 80) {
        precondition(maximumEventCount > 0, "maximumEventCount must be greater than zero")
        self.maximumEventCount = maximumEventCount
        self.events = []
        self.events.reserveCapacity(maximumEventCount)
        self.droppedEventCount = 0
    }

    /// Records one event, dropping the oldest event when the buffer is full.
    public func record(_ event: SSHClientLogEvent) {
        self.lock.lock()
        defer { self.lock.unlock() }

        if self.events.count == self.maximumEventCount {
            self.events.removeFirst()
            self.droppedEventCount += 1
        }

        self.events.append(event)
    }

    /// Removes all recorded events and resets the dropped-event counter.
    public func clear() {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.events.removeAll(keepingCapacity: true)
        self.droppedEventCount = 0
    }

    /// Returns an immutable snapshot of the current recorder contents.
    public func snapshot() -> SSHClientLogRecorderSnapshot {
        self.lock.lock()
        defer { self.lock.unlock() }
        return SSHClientLogRecorderSnapshot(
            events: self.events,
            maximumEventCount: self.maximumEventCount,
            droppedEventCount: self.droppedEventCount
        )
    }

    /// Builds a redacted diagnostic report from an optional error and current
    /// recorded log lines.
    public func diagnosticReport(for error: Error? = nil) -> String? {
        self.snapshot().diagnosticReport(for: error)
    }

    /// Returns a log handler that records matching events into this recorder.
    public func logHandler(
        minimumLevel: SSHClientLogLevel = .info
    ) -> SSHClientLogHandler {
        SSHClientLogHandler.recorder(self, minimumLevel: minimumLevel)
    }
}

public extension SSHClientLogHandler {
    /// Creates a log handler backed by a recorder.
    static func recorder(
        _ recorder: SSHClientLogRecorder,
        minimumLevel: SSHClientLogLevel = .info
    ) -> Self {
        Self.sink(minimumLevel: minimumLevel) { event in
            recorder.record(event)
        }
    }
}
