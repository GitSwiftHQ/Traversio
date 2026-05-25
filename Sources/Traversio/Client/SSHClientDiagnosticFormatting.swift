// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

public extension SSHClientLogEvent {
    /// A single redacted key-value log line suitable for support reports.
    var formattedLine: String {
        var fields = [
            "timestamp=\(sshDiagnosticQuoted(sshDiagnosticTimestamp(self.timestamp)))",
            "level=\(self.level.diagnosticName)",
            "category=\(self.category.rawValue)",
            "message=\(sshDiagnosticQuoted(sshDiagnosticRedacted(self.message)))",
        ]

        for key in self.metadata.keys.sorted() {
            guard let value = self.metadata[key] else {
                continue
            }
            fields.append("\(key)=\(sshDiagnosticQuoted(sshDiagnosticRedactedValue(forKey: key, value)))")
        }

        return fields.joined(separator: " ")
    }
}

public extension SSHConnectionFailure {
    /// A redacted multi-line support report for this connection setup failure.
    var diagnosticReport: String {
        SSHDiagnosticReportFormatter.connectionFailure(self)
    }
}

public extension SSHOperationFailure {
    /// A redacted multi-line support report for this operation failure.
    var diagnosticReport: String {
        SSHDiagnosticReportFormatter.operationFailure(self)
    }
}

public extension SSHPortLatencyError {
    /// A redacted multi-line support report for this latency measurement failure.
    var diagnosticReport: String {
        SSHDiagnosticReportFormatter.portLatencyFailure(self)
    }
}

private enum SSHDiagnosticReportFormatter {
    static func connectionFailure(_ failure: SSHConnectionFailure) -> String {
        let diagnostics = failure.diagnostics
        var lines = [
            "SSH connection failure",
            "message: \(sshDiagnosticRedacted(failure.message))",
            "stage: \(failure.stage.rawValue)",
            "code: \(failure.code.rawValue)",
            "endpoint: \(diagnostics.endpointHost):\(diagnostics.endpointPort)",
            "username: \(diagnostics.username)",
            "client-identification: \(diagnostics.clientIdentification)",
            "remote-identification: \(diagnostics.remoteIdentification ?? "none")",
        ]

        appendPreIdentificationLines(diagnostics.preIdentificationLines, to: &lines)
        appendRuntimePolicy(
            keepaliveIntervalNanoseconds: diagnostics.keepaliveIntervalNanoseconds,
            keepaliveReplyTimeoutNanoseconds: diagnostics.keepaliveReplyTimeoutNanoseconds,
            responseTimeoutNanoseconds: diagnostics.responseTimeoutNanoseconds,
            to: &lines
        )
        appendNegotiatedAlgorithms(diagnostics.negotiatedAlgorithms, to: &lines)
        appendServerExtensionInfo(
            didReceiveExtensionInfo: diagnostics.didReceiveServerExtensionInfo,
            extensionNames: diagnostics.serverExtensionNames,
            signatureAlgorithms: diagnostics.serverSignatureAlgorithms,
            to: &lines
        )
        appendRemoteDisconnect(diagnostics.remoteDisconnect, to: &lines)
        appendRemoteDebugMessages(diagnostics.remoteDebugMessages, to: &lines)

        if let callbackFailure = diagnostics.callbackFailure {
            lines.append("callback-failure-source: \(callbackFailure.source.rawValue)")
            lines.append("callback-failure-error-type: \(callbackFailure.errorType)")
            if let diagnosticCode = callbackFailure.diagnosticCode {
                lines.append(
                    "callback-failure-diagnostic-code: \(sshDiagnosticRedacted(diagnosticCode))"
                )
            }
            if let diagnosticSummary = callbackFailure.diagnosticSummary {
                lines.append(
                    "callback-failure-diagnostic-summary: \(sshDiagnosticRedacted(diagnosticSummary))"
                )
            }
        }

        return lines.joined(separator: "\n")
    }

    static func operationFailure(_ failure: SSHOperationFailure) -> String {
        let diagnostics = failure.diagnostics
        var lines = [
            "SSH operation failure",
            "message: \(sshDiagnosticRedacted(failure.message))",
            "scope: \(failure.scope.rawValue)",
            "code: \(failure.code.rawValue)",
            "endpoint: \(diagnostics.endpointHost):\(diagnostics.endpointPort)",
            "username: \(diagnostics.username)",
            "client-identification: \(diagnostics.clientIdentification)",
            "remote-identification: \(diagnostics.remoteIdentification)",
        ]

        appendRuntimePolicy(
            keepaliveIntervalNanoseconds: diagnostics.keepaliveIntervalNanoseconds,
            keepaliveReplyTimeoutNanoseconds: diagnostics.keepaliveReplyTimeoutNanoseconds,
            responseTimeoutNanoseconds: diagnostics.responseTimeoutNanoseconds,
            to: &lines
        )
        appendNegotiatedAlgorithms(diagnostics.negotiatedAlgorithms, to: &lines)
        appendServerExtensionInfo(
            didReceiveExtensionInfo: diagnostics.didReceiveServerExtensionInfo,
            extensionNames: diagnostics.serverExtensionNames,
            signatureAlgorithms: nil,
            to: &lines
        )
        appendRemoteDisconnect(diagnostics.remoteDisconnect, to: &lines)
        appendRemoteDebugMessages(diagnostics.remoteDebugMessages, to: &lines)

        if let localChannelID = diagnostics.localChannelID {
            lines.append("local-channel-id: \(localChannelID)")
        }
        if let remoteChannelID = diagnostics.remoteChannelID {
            lines.append("remote-channel-id: \(remoteChannelID)")
        }
        if let requestType = diagnostics.requestType {
            lines.append("request-type: \(requestType)")
        }
        if let sftpStatus = diagnostics.sftpStatus {
            lines.append("sftp-status-code: \(sftpStatus.code)")
            lines.append("sftp-status-name: \(sftpStatus.standardName ?? "unknown")")
            lines.append(
                "sftp-status-message: \(sftpStatus.message.map(sshDiagnosticRedacted) ?? "none")"
            )
            let languageTag = sftpStatus.languageTag.map(sshDiagnosticRedacted) ?? "none"
            lines.append("sftp-status-language-tag: \(languageTag)")
        }

        return lines.joined(separator: "\n")
    }

    static func portLatencyFailure(_ error: SSHPortLatencyError) -> String {
        var lines = [
            "SSH port latency failure",
            "message: \(sshDiagnosticRedacted(error.description))",
        ]

        switch error {
        case let .invalidSampleCount(sampleCount):
            lines.append("case: invalidSampleCount")
            lines.append("sample-count: \(sampleCount)")
        case let .invalidConnectTimeout(timeout):
            lines.append("case: invalidConnectTimeout")
            lines.append("connect-timeout: \(formattedDiagnosticTimeInterval(timeout))")
        case let .invalidFirstServerByteTimeout(timeout):
            lines.append("case: invalidFirstServerByteTimeout")
            lines.append("ssh-service-request-timeout: \(formattedDiagnosticTimeInterval(timeout))")
        case let .invalidDelayBetweenSamples(delay):
            lines.append("case: invalidDelayBetweenSamples")
            lines.append("delay-between-samples: \(formattedDiagnosticTimeInterval(delay))")
        case let .connectionTimedOut(endpointHost, endpointPort, timeout):
            lines.append("case: connectionTimedOut")
            lines.append("endpoint: \(sshDiagnosticRedacted(endpointHost)):\(endpointPort)")
            lines.append("measurement-stage: route-setup")
            lines.append("timeout: \(formattedDiagnosticTimeInterval(timeout))")
        case let .firstServerByteTimedOut(endpointHost, endpointPort, timeout):
            lines.append("case: firstServerByteTimedOut")
            lines.append("endpoint: \(sshDiagnosticRedacted(endpointHost)):\(endpointPort)")
            lines.append("measurement-stage: ssh-service-request")
            lines.append("timeout: \(formattedDiagnosticTimeInterval(timeout))")
        case let .noSuccessfulSamples(endpointHost, endpointPort, failureCount):
            lines.append("case: noSuccessfulSamples")
            lines.append("endpoint: \(sshDiagnosticRedacted(endpointHost)):\(endpointPort)")
            lines.append("failure-count: \(failureCount)")
        }

        return lines.joined(separator: "\n")
    }

    private static func appendPreIdentificationLines(
        _ preIdentificationLines: [String],
        to lines: inout [String]
    ) {
        if preIdentificationLines.isEmpty {
            lines.append("pre-identification-lines: none")
            return
        }

        for (index, line) in preIdentificationLines.enumerated() {
            lines.append("pre-identification-line[\(index)]: \(sshDiagnosticRedacted(line))")
        }
    }

    private static func appendNegotiatedAlgorithms(
        _ algorithms: SSHNegotiatedTransportAlgorithms?,
        to lines: inout [String]
    ) {
        guard let algorithms else {
            lines.append("negotiated-algorithms: none")
            return
        }

        lines.append("key-exchange-algorithm: \(algorithms.keyExchangeAlgorithm)")
        lines.append("server-host-key-algorithm: \(algorithms.serverHostKeyAlgorithm)")
        lines.append(
            "encryption-client-to-server: \(algorithms.encryptionAlgorithmClientToServer)"
        )
        lines.append(
            "encryption-server-to-client: \(algorithms.encryptionAlgorithmServerToClient)"
        )
        lines.append("mac-client-to-server: \(algorithms.macAlgorithmClientToServer)")
        lines.append("mac-server-to-client: \(algorithms.macAlgorithmServerToClient)")
        lines.append(
            "compression-client-to-server: \(algorithms.compressionAlgorithmClientToServer)"
        )
        lines.append(
            "compression-server-to-client: \(algorithms.compressionAlgorithmServerToClient)"
        )
        lines.append(
            "effective-integrity-client-to-server: \(algorithms.effectiveIntegrityAlgorithmClientToServer)"
        )
        lines.append(
            "effective-integrity-server-to-client: \(algorithms.effectiveIntegrityAlgorithmServerToClient)"
        )
        lines.append("uses-strict-key-exchange: \(algorithms.usesStrictKeyExchange)")
    }

    private static func appendRuntimePolicy(
        keepaliveIntervalNanoseconds: UInt64?,
        keepaliveReplyTimeoutNanoseconds: UInt64?,
        responseTimeoutNanoseconds: UInt64?,
        to lines: inout [String]
    ) {
        lines.append(
            "keepalive-interval: \(formattedOptionalDiagnosticInterval(keepaliveIntervalNanoseconds))"
        )
        lines.append(
            "keepalive-reply-timeout: \(formattedOptionalDiagnosticInterval(keepaliveReplyTimeoutNanoseconds))"
        )
        lines.append(
            "response-timeout: \(formattedOptionalDiagnosticInterval(responseTimeoutNanoseconds))"
        )
    }

    private static func appendServerExtensionInfo(
        didReceiveExtensionInfo: Bool,
        extensionNames: [String],
        signatureAlgorithms: [String]?,
        to lines: inout [String]
    ) {
        lines.append("received-server-extension-info: \(didReceiveExtensionInfo)")
        lines.append(
            "server-extension-names: \(extensionNames.isEmpty ? "none" : extensionNames.joined(separator: ","))"
        )
        if let signatureAlgorithms {
            lines.append(
                "server-signature-algorithms: \(signatureAlgorithms.joined(separator: ","))"
            )
        }
    }

    private static func appendRemoteDisconnect(
        _ remoteDisconnect: SSHRemoteDisconnect?,
        to lines: inout [String]
    ) {
        guard let remoteDisconnect else {
            return
        }

        lines.append("remote-disconnect-reason-code: \(remoteDisconnect.reasonCode)")
        let description = remoteDisconnect.description.isEmpty
            ? "none"
            : sshDiagnosticRedacted(remoteDisconnect.description)
        lines.append(
            "remote-disconnect-description: \(description)"
        )
        let languageTag = remoteDisconnect.languageTag.isEmpty
            ? "none"
            : sshDiagnosticRedacted(remoteDisconnect.languageTag)
        lines.append("remote-disconnect-language-tag: \(languageTag)")
    }

    private static func appendRemoteDebugMessages(
        _ debugMessages: [SSHRemoteDebugMessage],
        to lines: inout [String]
    ) {
        if debugMessages.isEmpty {
            lines.append("remote-debug-messages: none")
            return
        }

        for (index, debugMessage) in debugMessages.enumerated() {
            let languageTag = debugMessage.languageTag.isEmpty
                ? "none"
                : sshDiagnosticRedacted(debugMessage.languageTag)
            lines.append(
                "remote-debug-message[\(index)]: alwaysDisplay=\(debugMessage.alwaysDisplay) languageTag=\(languageTag) message=\(sshDiagnosticRedacted(debugMessage.message))"
            )
        }
    }
}

private func formattedOptionalDiagnosticInterval(_ nanoseconds: UInt64?) -> String {
    guard let nanoseconds else {
        return "disabled"
    }

    let seconds = Double(nanoseconds) / 1_000_000_000
    if seconds.rounded() == seconds {
        return "\(Int(seconds))s"
    }

    var rendered = String(format: "%.3f", seconds)
    while rendered.last == "0" {
        rendered.removeLast()
    }
    if rendered.last == "." {
        rendered.removeLast()
    }
    return "\(rendered)s"
}

private func formattedDiagnosticTimeInterval(_ timeInterval: TimeInterval) -> String {
    guard timeInterval.isFinite else {
        return "\(timeInterval)s"
    }
    guard timeInterval >= 0 else {
        return "\(timeInterval)s"
    }

    let nanoseconds = (timeInterval * 1_000_000_000).rounded()
    guard nanoseconds <= Double(UInt64.max) else {
        return "\(timeInterval)s"
    }

    return formattedOptionalDiagnosticInterval(UInt64(nanoseconds))
}

private extension SSHClientLogLevel {
    var diagnosticName: String {
        switch self {
        case .debug:
            return "debug"
        case .info:
            return "info"
        case .notice:
            return "notice"
        case .warning:
            return "warning"
        case .error:
            return "error"
        }
    }
}

func sshDiagnosticTimestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}

func sshDiagnosticQuoted(_ value: String) -> String {
    let escaped = value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
    return "\"\(escaped)\""
}

func sshDiagnosticRedactedMetadata(_ metadata: [String: String]) -> [String: String] {
    var redacted: [String: String] = [:]
    redacted.reserveCapacity(metadata.count)

    for (key, value) in metadata {
        redacted[key] = sshDiagnosticRedactedValue(forKey: key, value)
    }

    return redacted
}

func sshDiagnosticRedactedValue(forKey key: String, _ value: String) -> String {
    if sshDiagnosticMetadataKeyIsSensitive(key) {
        return "<redacted>"
    }
    return sshDiagnosticRedacted(value)
}

func sshDiagnosticRedacted(_ value: String) -> String {
    var result = value
    for pattern in sshDiagnosticSensitiveValuePatterns {
        result = pattern.stringByReplacingMatches(
            in: result,
            range: NSRange(result.startIndex..., in: result),
            withTemplate: "$1$2<redacted>"
        )
    }
    return result
}

private func sshDiagnosticMetadataKeyIsSensitive(_ key: String) -> Bool {
    let normalized = key
        .lowercased()
        .filter { $0.isLetter || $0.isNumber }

    return [
        "password",
        "passphrase",
        "privatekey",
        "secret",
        "token",
        "credential",
        "authorization",
    ].contains { normalized.contains($0) }
}

private let sshDiagnosticSensitiveValuePatterns: [NSRegularExpression] = [
    try! NSRegularExpression(
        pattern: "(?i)(authorization)(\\s*[:=]\\s*)[^\\n\\r]+"
    ),
    try! NSRegularExpression(
        pattern: "(?i)(password|passphrase|private[-_ ]?key|secret|token|credential)(\\s*[:=]\\s*)([^\\s\\\"'&,;]+)"
    ),
]
