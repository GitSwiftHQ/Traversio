// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

enum SSHWireError: Error, Equatable, Sendable {
    case insufficientBytes(expected: Int, remaining: Int)
    case invalidBoolean(UInt8)
    case invalidUTF8String
    case invalidNameList
    case invalidMPInt
    case unknownMessageType(UInt8)
    case trailingMessageBytes(Int)
    case invalidKeyExchangeCookieLength(Int)
    case emptyRequiredNameList(String)
    case identificationTooLong
    case invalidIdentification
    case unsupportedProtocolVersion(String)
    case unexpectedPreIdentificationLine
    case invalidPacketLength(UInt32)
    case invalidPacketPadding(UInt8)
    case packetTooLarge(UInt32)
}
