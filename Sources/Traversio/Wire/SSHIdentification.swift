// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHIdentification: Equatable, Sendable {
    package static let supportedProtocolVersions: Set<String> = ["2.0", "1.99"]

    package let rawValue: String
    package let protocolVersion: String
    package let softwareVersion: String
    package let comments: String?

    package init(rawValue: String) throws {
        guard rawValue.utf8.count <= 253 else {
            throw SSHWireError.identificationTooLong
        }

        guard !rawValue.isEmpty, !rawValue.utf8.contains(0) else {
            throw SSHWireError.invalidIdentification
        }

        guard rawValue.hasPrefix("SSH-") else {
            throw SSHWireError.invalidIdentification
        }

        let remainder = rawValue.dropFirst(4)
        guard let separatorIndex = remainder.firstIndex(of: "-") else {
            throw SSHWireError.invalidIdentification
        }

        let protocolVersion = String(remainder[..<separatorIndex])
        let softwareAndComments = remainder[remainder.index(after: separatorIndex)...]

        guard Self.supportedProtocolVersions.contains(protocolVersion) else {
            throw SSHWireError.unsupportedProtocolVersion(protocolVersion)
        }

        let softwareVersion: String
        let comments: String?
        if let commentSeparator = softwareAndComments.firstIndex(of: " ") {
            softwareVersion = String(softwareAndComments[..<commentSeparator])
            let commentStart = softwareAndComments.index(after: commentSeparator)
            comments = String(softwareAndComments[commentStart...])
        } else {
            softwareVersion = String(softwareAndComments)
            comments = nil
        }

        guard Self.isValidVersionToken(protocolVersion) else {
            throw SSHWireError.invalidIdentification
        }

        guard Self.isValidVersionToken(softwareVersion) else {
            throw SSHWireError.invalidIdentification
        }

        if let comments, !Self.isValidComment(comments) {
            throw SSHWireError.invalidIdentification
        }

        self.rawValue = rawValue
        self.protocolVersion = protocolVersion
        self.softwareVersion = softwareVersion
        self.comments = comments
    }

    package init(
        protocolVersion: String = "2.0",
        softwareVersion: String,
        comments: String? = nil
    ) throws {
        let rawValue: String
        if let comments {
            rawValue = "SSH-\(protocolVersion)-\(softwareVersion) \(comments)"
        } else {
            rawValue = "SSH-\(protocolVersion)-\(softwareVersion)"
        }

        try self.init(rawValue: rawValue)
    }

    package init(
        uncheckedRawValue rawValue: String,
        protocolVersion: String,
        softwareVersion: String,
        comments: String? = nil
    ) {
        self.rawValue = rawValue
        self.protocolVersion = protocolVersion
        self.softwareVersion = softwareVersion
        self.comments = comments
    }

    package func serializedBytes() -> [UInt8] {
        Array(self.rawValue.utf8) + [0x0d, 0x0a]
    }

    private static func isValidVersionToken(_ value: String) -> Bool {
        guard !value.isEmpty else {
            return false
        }

        return value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && scalar.value >= 0x21 && scalar.value <= 0x7e && scalar.value != 0x2d
        }
    }

    private static func isValidComment(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && scalar.value >= 0x20 && scalar.value <= 0x7e
        }
    }
}
