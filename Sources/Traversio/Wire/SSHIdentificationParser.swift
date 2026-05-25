// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHIdentificationParserEvent: Equatable, Sendable {
    case preIdentificationLine(String)
    case identification(SSHIdentification)
}

package struct SSHIdentificationParser: Sendable {
    package enum Role: Sendable {
        case client
        case server
    }

    private let role: Role
    private var bufferedBytes: [UInt8]

    package init(role: Role) {
        self.role = role
        self.bufferedBytes = []
    }

    package mutating func append(bytes: [UInt8]) {
        self.bufferedBytes.append(contentsOf: bytes)
    }

    package mutating func takeBufferedBytes() -> [UInt8] {
        defer { self.bufferedBytes.removeAll(keepingCapacity: false) }
        return self.bufferedBytes
    }

    package mutating func nextEvent() throws -> SSHIdentificationParserEvent? {
        while let lineFeedIndex = self.bufferedBytes.firstIndex(of: 0x0a) {
            let line = Array(self.bufferedBytes[...lineFeedIndex])
            self.bufferedBytes.removeFirst(lineFeedIndex + 1)

            guard line.count <= 255 else {
                throw SSHWireError.identificationTooLong
            }

            let rawLineBytes: [UInt8]
            if line.count >= 2, line[line.count - 2] == 0x0d {
                rawLineBytes = Array(line.dropLast(2))
            } else {
                rawLineBytes = Array(line.dropLast())
            }

            guard !rawLineBytes.contains(0) else {
                throw SSHWireError.invalidIdentification
            }

            if rawLineBytes.starts(with: Array("SSH-".utf8)) {
                let rawValue = String(decoding: rawLineBytes, as: UTF8.self)
                return .identification(try SSHIdentification(rawValue: rawValue))
            }

            switch self.role {
            case .client:
                return .preIdentificationLine(String(decoding: rawLineBytes, as: UTF8.self))
            case .server:
                throw SSHWireError.unexpectedPreIdentificationLine
            }
        }

        if self.bufferedBytes.count > 255 {
            throw SSHWireError.identificationTooLong
        }

        return nil
    }

    package mutating func nextIdentification() throws -> SSHIdentification? {
        while let event = try self.nextEvent() {
            switch event {
            case .preIdentificationLine:
                continue
            case let .identification(identification):
                return identification
            }
        }

        return nil
    }
}
