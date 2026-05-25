// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import OSLog

@available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, visionOS 1.0, *)
extension SSHClientLogHandler {
    /// Creates a log handler that writes redacted Traversio events to OSLog.
    public static func osLog(
        _ logger: Logger,
        minimumLevel: SSHClientLogLevel = .info
    ) -> Self {
        Self.sink(minimumLevel: minimumLevel) { event in
            logger.log(
                level: sshOSLogType(for: event.level),
                "\(sshOSLogMessage(for: event), privacy: .public)"
            )
        }
    }

    /// Creates an OSLog-backed handler from a subsystem and category.
    public static func osLog(
        subsystem: String,
        category: String,
        minimumLevel: SSHClientLogLevel = .info
    ) -> Self {
        self.osLog(
            Logger(subsystem: subsystem, category: category),
            minimumLevel: minimumLevel
        )
    }
}

@available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, visionOS 1.0, *)
func sshOSLogType(for level: SSHClientLogLevel) -> OSLogType {
    switch level {
    case .debug:
        return .debug
    case .info:
        return .info
    case .notice:
        return .default
    case .warning:
        return .error
    case .error:
        return .fault
    }
}

func sshOSLogMessage(for event: SSHClientLogEvent) -> String {
    let prefix = "[\(event.category.rawValue)]"
    let metadataDescription = sshOSLogMetadataDescription(event.metadata)
    guard !metadataDescription.isEmpty else {
        return "\(prefix) \(sshDiagnosticRedacted(event.message))"
    }

    return "\(prefix) \(sshDiagnosticRedacted(event.message)) \(metadataDescription)"
}

func sshOSLogMetadataDescription(_ metadata: [String: String]) -> String {
    guard !metadata.isEmpty else {
        return ""
    }

    return metadata
        .sorted { lhs, rhs in
            lhs.key < rhs.key
        }
        .map { key, value in
            "\(key)=\(sshDiagnosticRedactedValue(forKey: key, value))"
        }
        .joined(separator: " ")
}
