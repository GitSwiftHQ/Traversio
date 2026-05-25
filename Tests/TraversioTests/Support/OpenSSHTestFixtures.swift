// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing

func loadBundledOpenSSHFixture(named name: String) throws -> String {
    switch name {
    case "ed25519_1":
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQAAAJjnj4Ao54+A
        KAAAAAtzc2gtZWQyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQ
        AAAED3KgoDbjR54V7bdNpfKlQY5m20UK1QaHytkCR+6rZEDFOG6kY7Rf4UtCFvPwKgo/Bz
        tXck2xC4a2WyA34XtIwZAAAAE0VEMjU1MTkgdGVzdCBrZXkgIzEBAg==
        -----END OPENSSH PRIVATE KEY-----
        """
    case "ed25519_1-cert.pub":
        """
        ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIxzuxl4z3uwAIslne8Huft+1n1IhHAlNbWZkQyyECCGAAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZAAAAAAAAAAgAAAACAAAABmp1bGl1cwAAABIAAAAFaG9zdDEAAAAFaG9zdDIAAAAANowB8AAAAABNHmBwAAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQAAAFMAAAALc3NoLWVkMjU1MTkAAABABGTn+Bmz86Ajk+iqKCSdP5NClsYzn4alJd0V5bizhP0Kumc/HbqQfSt684J1WdSzih+EjvnTgBhK9jTBKb90AQ== ED25519 test key #1
        """
    case "ecdsa_1-cert.pub":
        """
        ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgOtFRnMigkGliaYfPmX5IidVWfV3tRH6lqRXv0l8bvKoAAAAIbmlzdHAyNTYAAABBBAxZW5ZDq1vcnSlYbTPvQGN3PbGgRO0ht5Rcd/JwWr5AAw2iPY4d/5Lxvybfb6ZttqsKJJUwhg38wpF5CCmlpQcAAAAAAAAABwAAAAIAAAAGanVsaXVzAAAAEgAAAAVob3N0MQAAAAVob3N0MgAAAAA2jAHwAAAAAE0eYHAAAAAAAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxZW5ZDq1vcnSlYbTPvQGN3PbGgRO0ht5Rcd/JwWr5AAw2iPY4d/5Lxvybfb6ZttqsKJJUwhg38wpF5CCmlpQcAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIHbxGwTnue7KxhHXGFvRcxBnekhQ3Qx84vV/Vs4oVCrpAAAAIQC7vk2+d14aS7td7kVXLQn392oALjEBzMZoDvT1vT/zOA== ECDSA test key #1
        """
    default:
        throw OpenSSHTestFixtureError.unknownFixture(name)
    }
}

func loadBundledOpenSSHAuthorizedKeyBlob(named name: String) throws -> [UInt8] {
    let line = try loadBundledOpenSSHFixture(named: name)
        .split(whereSeparator: \.isNewline)
        .first.map(String.init) ?? ""
    let fields = line.split(separator: " ", omittingEmptySubsequences: true)
    let encodedKey = try #require(fields.count >= 2 ? String(fields[1]) : nil)
    let keyData = try #require(Data(base64Encoded: encodedKey))
    return Array(keyData)
}

private enum OpenSSHTestFixtureError: Error {
    case unknownFixture(String)
}
