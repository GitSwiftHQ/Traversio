// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Network
enum SSHKnownHostsError: Error, Equatable, Sendable {
    case noMatchingHostKey(SSHSocketEndpoint)
}
package struct SSHKnownHostsLookup: Equatable, Sendable {
    let endpoint: SSHSocketEndpoint
    let additionalLookupNames: [String]

    init(
        endpoint: SSHSocketEndpoint,
        additionalLookupNames: [String] = []
    ) {
        self.endpoint = endpoint
        self.additionalLookupNames = additionalLookupNames
    }
}
private enum SSHKnownHostsEntryMarker: Equatable, Sendable {
    case none
    case revoked
    case certificateAuthority
}
private struct SSHKnownHostsEntry: Equatable, Sendable {
    let marker: SSHKnownHostsEntryMarker
    let patternList: SSHKnownHostPatternList
    let trustedHostKey: SSHTrustedHostKey
}
private struct SSHKnownHostsMatch: Equatable, Sendable {
    var trustedHostKeys: [SSHTrustedHostKey] = []
    var revokedHostKeys: [SSHTrustedHostKey] = []
    var trustedCertificateAuthorityKeys: [SSHTrustedHostKey] = []

    var hasAnyMatch: Bool {
        !self.trustedHostKeys.isEmpty ||
            !self.revokedHostKeys.isEmpty ||
            !self.trustedCertificateAuthorityKeys.isEmpty
    }
}
private struct SSHKnownHostPatternList: Equatable, Sendable {
    let subpatterns: [SSHKnownHostSubpattern]

    func matches(anyOf lookupNames: [String]) -> Bool {
        var foundPositiveMatch = false

        for subpattern in self.subpatterns where subpattern.matches(anyOf: lookupNames) {
            if subpattern.isNegated {
                return false
            }
            foundPositiveMatch = true
        }

        return foundPositiveMatch
    }
}
private struct SSHKnownHostSubpattern: Equatable, Sendable {
    let isNegated: Bool
    let matcher: SSHKnownHostPatternMatcher

    func matches(anyOf lookupNames: [String]) -> Bool {
        lookupNames.contains(where: self.matcher.matches)
    }
}
private enum SSHKnownHostPatternMatcher: Equatable, Sendable {
    case plain(String)
    case hashed(salt: [UInt8], hash: [UInt8])
    case cidr(SSHKnownHostCIDRRange)

    func matches(_ lookupName: String) -> Bool {
        switch self {
        case let .plain(pattern):
            return SSHWildcardPatternMatcher.matches(
                lookupName,
                pattern: pattern
            )
        case let .hashed(salt, hash):
            let authenticationCode = HMAC<Insecure.SHA1>.authenticationCode(
                for: Data(lookupName.utf8),
                using: SymmetricKey(data: Data(salt))
            )
            return Array(authenticationCode) == hash
        case let .cidr(range):
            return range.matches(lookupName)
        }
    }
}
private enum SSHKnownHostIPAddressFamily: Equatable, Sendable {
    case ipv4
    case ipv6
}
private struct SSHKnownHostIPAddress: Equatable, Sendable {
    let family: SSHKnownHostIPAddressFamily
    let rawBytes: [UInt8]

    init?(_ rawValue: String) {
        if let ipv4Address = IPv4Address(rawValue) {
            self.family = .ipv4
            self.rawBytes = Array(ipv4Address.rawValue)
            return
        }

        if let ipv6Address = IPv6Address(rawValue) {
            self.family = .ipv6
            self.rawBytes = Array(ipv6Address.rawValue)
            return
        }

        return nil
    }

    var bitCount: Int {
        self.rawBytes.count * 8
    }
}
private struct SSHKnownHostCIDRRange: Equatable, Sendable {
    let networkAddress: SSHKnownHostIPAddress
    let prefixLength: Int

    func matches(_ lookupName: String) -> Bool {
        guard let lookupAddress = SSHKnownHostIPAddress(lookupName),
              lookupAddress.family == self.networkAddress.family else {
            return false
        }

        return Self.prefixMatches(
            lookupAddress.rawBytes,
            networkAddressBytes: self.networkAddress.rawBytes,
            prefixLength: self.prefixLength
        )
    }

    static func parse(_ rawValue: String) -> SSHKnownHostCIDRRange? {
        let components = rawValue.split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard components.count == 2,
              !components[0].isEmpty,
              !components[1].isEmpty,
              let networkAddress = SSHKnownHostIPAddress(String(components[0])),
              let prefixLength = Int(components[1]),
              (0...networkAddress.bitCount).contains(prefixLength),
              Self.hostBitsAreZero(
                networkAddress.rawBytes,
                prefixLength: prefixLength
              ) else {
            return nil
        }

        return SSHKnownHostCIDRRange(
            networkAddress: networkAddress,
            prefixLength: prefixLength
        )
    }

    private static func prefixMatches(
        _ lookupAddressBytes: [UInt8],
        networkAddressBytes: [UInt8],
        prefixLength: Int
    ) -> Bool {
        let fullByteCount = prefixLength / 8
        let partialBitCount = prefixLength % 8

        if fullByteCount > 0,
           lookupAddressBytes.prefix(fullByteCount) != networkAddressBytes.prefix(fullByteCount) {
            return false
        }

        guard partialBitCount > 0 else {
            return true
        }

        let mask = UInt8(0xff << (8 - partialBitCount))
        return (lookupAddressBytes[fullByteCount] & mask) ==
            (networkAddressBytes[fullByteCount] & mask)
    }

    private static func hostBitsAreZero(
        _ networkAddressBytes: [UInt8],
        prefixLength: Int
    ) -> Bool {
        let fullByteCount = prefixLength / 8
        let partialBitCount = prefixLength % 8

        if partialBitCount > 0 {
            let hostMask = UInt8(0xff >> partialBitCount)
            guard (networkAddressBytes[fullByteCount] & hostMask) == 0 else {
                return false
            }
        }

        let trailingByteIndex = partialBitCount > 0
            ? fullByteCount + 1
            : fullByteCount
        guard trailingByteIndex <= networkAddressBytes.count else {
            return false
        }

        return networkAddressBytes[trailingByteIndex...].allSatisfy { $0 == 0 }
    }
}
package struct SSHKnownHosts: Equatable, Sendable {
    private static let hashedHostMagic = "|1|"
    private static let hashedHostDelimiter: Character = "|"
    private static let sha1ByteCount = 20

    private var entries: [SSHKnownHostsEntry] = []

    package init() {}

    package init(contents: String) {
        self.load(contents: contents)
    }

    package static func load(from path: String) throws -> SSHKnownHosts {
        let contents = try String(contentsOfFile: path, encoding: .utf8)
        return SSHKnownHosts(contents: contents)
    }

    mutating func load(contents: String) {
        for line in contents.split(whereSeparator: \.isNewline) {
            guard let entry = Self.parseLine(String(line)) else {
                continue
            }

            self.entries.append(entry)
        }
    }

    func trustedHostKeys(
        matching endpoint: SSHSocketEndpoint,
        additionalLookupNames: [String] = []
    ) -> [SSHTrustedHostKey] {
        self.match(
            for: SSHKnownHostsLookup(
                endpoint: endpoint,
                additionalLookupNames: additionalLookupNames
            )
        ).trustedHostKeys
    }

    package func requireTrustPolicy(
        for endpoint: SSHSocketEndpoint,
        additionalLookupNames: [String] = []
    ) throws -> SSHHostKeyTrustPolicy {
        try self.requireTrustPolicy(
            for: SSHKnownHostsLookup(
                endpoint: endpoint,
                additionalLookupNames: additionalLookupNames
            )
        )
    }

    package func requireTrustPolicy(
        for lookup: SSHKnownHostsLookup
    ) throws -> SSHHostKeyTrustPolicy {
        let match = self.match(for: lookup)
        guard match.hasAnyMatch else {
            throw SSHKnownHostsError.noMatchingHostKey(lookup.endpoint)
        }

        if match.revokedHostKeys.isEmpty,
           match.trustedCertificateAuthorityKeys.isEmpty,
           match.trustedHostKeys.count == 1,
           let trustedHostKey = match.trustedHostKeys.first {
            return .requireMatch(trustedHostKey)
        }

        if match.revokedHostKeys.isEmpty,
           match.trustedCertificateAuthorityKeys.isEmpty {
            return .requireMatchAny(match.trustedHostKeys)
        }

        return .knownHosts(
            trustedHostKeys: match.trustedHostKeys,
            revokedHostKeys: match.revokedHostKeys,
            trustedCertificateAuthorityKeys: match.trustedCertificateAuthorityKeys
        )
    }

    private func match(for lookup: SSHKnownHostsLookup) -> SSHKnownHostsMatch {
        let primaryLookupNames = Self.primaryLookupNames(
            for: lookup.endpoint,
            additionalLookupNames: lookup.additionalLookupNames
        )
        let primaryMatch = self.matches(forLookupNames: primaryLookupNames)
        if primaryMatch.hasAnyMatch {
            return primaryMatch
        }

        guard lookup.endpoint.port != 22 else {
            return SSHKnownHostsMatch()
        }

        return self.matches(
            forLookupNames: Self.rawLookupNames(
                for: lookup.endpoint,
                additionalLookupNames: lookup.additionalLookupNames
            )
        )
    }

    private func matches(forLookupNames names: [String]) -> SSHKnownHostsMatch {
        var match = SSHKnownHostsMatch()

        for entry in self.entries where entry.patternList.matches(anyOf: names) {
            switch entry.marker {
            case .none:
                if !match.trustedHostKeys.contains(where: {
                    $0.rawRepresentation == entry.trustedHostKey.rawRepresentation
                }) {
                    match.trustedHostKeys.append(entry.trustedHostKey)
                }
            case .revoked:
                if !match.revokedHostKeys.contains(where: {
                    $0.rawRepresentation == entry.trustedHostKey.rawRepresentation
                }) {
                    match.revokedHostKeys.append(entry.trustedHostKey)
                }
            case .certificateAuthority:
                if !match.trustedCertificateAuthorityKeys.contains(where: {
                    $0.rawRepresentation == entry.trustedHostKey.rawRepresentation
                }) {
                    match.trustedCertificateAuthorityKeys.append(entry.trustedHostKey)
                }
            }
        }

        return match
    }

    private static func parseLine(_ rawLine: String) -> SSHKnownHostsEntry? {
        let trimmedLine = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedLine.isEmpty, !trimmedLine.hasPrefix("#") else {
            return nil
        }

        let fields = trimmedLine.split(whereSeparator: \.isWhitespace)
        guard !fields.isEmpty else {
            return nil
        }

        var fieldIndex = 0
        let marker: SSHKnownHostsEntryMarker
        if fields[fieldIndex].hasPrefix("@") {
            guard let parsedMarker = Self.parseSupportedMarker(String(fields[fieldIndex])) else {
                return nil
            }
            marker = parsedMarker
            fieldIndex += 1
        } else {
            marker = .none
        }

        guard fields.count >= fieldIndex + 3 else {
            return nil
        }

        let rawPatternList = String(fields[fieldIndex])
        let declaredAlgorithm = String(fields[fieldIndex + 1])
        let encodedKey = String(fields[fieldIndex + 2])

        guard let keyData = Data(base64Encoded: encodedKey) else {
            return nil
        }

        guard let trustedHostKey = try? SSHTrustedHostKey(rawRepresentation: Array(keyData)),
              trustedHostKey.algorithmName == declaredAlgorithm else {
            return nil
        }

        guard let patternList = Self.parsePatternList(rawPatternList) else {
            return nil
        }

        return SSHKnownHostsEntry(
            marker: marker,
            patternList: patternList,
            trustedHostKey: trustedHostKey
        )
    }

    private static func parseSupportedMarker(
        _ markerField: String
    ) -> SSHKnownHostsEntryMarker? {
        switch markerField {
        case "@revoked":
            return .revoked
        case "@cert-authority":
            return .certificateAuthority
        default:
            return nil
        }
    }

    private static func parsePatternList(
        _ rawPatternList: String
    ) -> SSHKnownHostPatternList? {
        let rawSubpatterns = rawPatternList.split(
            separator: ",",
            omittingEmptySubsequences: false
        )
        let supportedSubpatterns = rawSubpatterns.compactMap { rawSubpattern in
            Self.parseSupportedSubpattern(String(rawSubpattern))
        }
        guard !supportedSubpatterns.isEmpty else {
            return nil
        }

        return SSHKnownHostPatternList(subpatterns: supportedSubpatterns)
    }

    private static func parseSupportedSubpattern(
        _ rawSubpattern: String
    ) -> SSHKnownHostSubpattern? {
        guard !rawSubpattern.isEmpty else {
            return nil
        }

        let isNegated = rawSubpattern.hasPrefix("!")
        let pattern = isNegated ? String(rawSubpattern.dropFirst()) : rawSubpattern
        guard !pattern.isEmpty else {
            return nil
        }

        if let hashedPattern = Self.parseHashedPattern(pattern) {
            return SSHKnownHostSubpattern(
                isNegated: isNegated,
                matcher: hashedPattern
            )
        }

        if let cidrRange = SSHKnownHostCIDRRange.parse(pattern) {
            return SSHKnownHostSubpattern(
                isNegated: isNegated,
                matcher: .cidr(cidrRange)
            )
        }

        guard Self.isSupportedPlainPattern(pattern) else {
            return nil
        }

        return SSHKnownHostSubpattern(
            isNegated: isNegated,
            matcher: .plain(Self.normalizePattern(pattern))
        )
    }

    private static func parseHashedPattern(
        _ pattern: String
    ) -> SSHKnownHostPatternMatcher? {
        guard pattern.hasPrefix(Self.hashedHostMagic) else {
            return nil
        }

        let remainder = String(pattern.dropFirst(Self.hashedHostMagic.count))
        let components = remainder.split(
            separator: Self.hashedHostDelimiter,
            omittingEmptySubsequences: false
        )
        guard components.count == 2,
              let saltData = Data(base64Encoded: String(components[0])),
              let hashData = Data(base64Encoded: String(components[1])),
              saltData.count == Self.sha1ByteCount,
              hashData.count == Self.sha1ByteCount else {
            return nil
        }

        return .hashed(salt: Array(saltData), hash: Array(hashData))
    }

    private static func isSupportedPlainPattern(_ pattern: String) -> Bool {
        guard !pattern.isEmpty else {
            return false
        }

        return !pattern.contains(Self.hashedHostDelimiter) &&
            !pattern.contains("/")
    }

    private static func primaryLookupNames(
        for endpoint: SSHSocketEndpoint,
        additionalLookupNames: [String]
    ) -> [String] {
        let normalizedLookupNames = Self.normalizedLookupNames(
            primaryHost: endpoint.host,
            additionalLookupNames: additionalLookupNames
        )

        guard endpoint.port != 22 else {
            return normalizedLookupNames
        }

        return normalizedLookupNames.map { "[\($0)]:\(endpoint.port)" }
    }

    private static func rawLookupNames(
        for endpoint: SSHSocketEndpoint,
        additionalLookupNames: [String]
    ) -> [String] {
        Self.normalizedLookupNames(
            primaryHost: endpoint.host,
            additionalLookupNames: additionalLookupNames
        )
    }

    private static func normalizedLookupNames(
        primaryHost: String,
        additionalLookupNames: [String]
    ) -> [String] {
        var normalizedNames: [String] = []

        for rawName in [primaryHost] + additionalLookupNames {
            let normalizedName = Self.normalizeHost(rawName)
            guard !normalizedName.isEmpty,
                  !normalizedNames.contains(normalizedName) else {
                continue
            }
            normalizedNames.append(normalizedName)
        }

        return normalizedNames
    }

    private static func normalizeHost(_ host: String) -> String {
        let normalizedHost: String
        guard host.hasPrefix("["),
              host.hasSuffix("]") else {
            normalizedHost = host
            return normalizedHost.lowercased()
        }

        normalizedHost = String(host.dropFirst().dropLast())
        return normalizedHost.lowercased()
    }

    private static func normalizePattern(_ pattern: String) -> String {
        pattern.lowercased()
    }
}
