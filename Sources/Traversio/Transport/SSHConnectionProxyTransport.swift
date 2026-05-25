// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Darwin
import Foundation
enum SSHConnectionProxyTransport {
    private static let httpHeaderLimit = 16 * 1024

    static func makeTransportHandle(
        to endpoint: SSHSocketEndpoint,
        proxy: SSHConnectionProxy?,
        transportHandleFactory: @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
    ) async throws -> SSHClientTransportHandle {
        guard let proxy else {
            return try await transportHandleFactory(endpoint)
        }

        switch proxy {
        case let .socks5(configuration):
            _ = try self.socks5Methods(for: configuration.authentication)
        case let .httpConnect(configuration):
            _ = try self.makeHTTPConnectRequest(
                authority: try self.httpConnectAuthority(for: endpoint),
                authentication: configuration.authentication
            )
        }

        let rootTransportHandle = try await transportHandleFactory(proxy.endpoint)
        let proxiedTransport = SSHBufferedByteStreamTransport(
            base: rootTransportHandle.transport
        )
        let proxiedHandle = SSHClientTransportHandle(
            transport: proxiedTransport,
            closeOperation: {
                await rootTransportHandle.closeOperation?()
            },
            abortOperation: {
                if let abortOperation = rootTransportHandle.abortOperation {
                    await abortOperation()
                } else {
                    await rootTransportHandle.closeOperation?()
                }
            }
        )

        do {
            switch proxy {
            case let .socks5(configuration):
                try await self.negotiateSOCKS5(
                    target: endpoint,
                    proxy: configuration,
                    transport: proxiedTransport
                )
            case let .httpConnect(configuration):
                try await self.negotiateHTTPConnect(
                    target: endpoint,
                    proxy: configuration,
                    transport: proxiedTransport
                )
            }
        } catch {
            await proxiedHandle.close()
            throw error
        }

        return proxiedHandle
    }

    static func makeTransportHandle(
        to endpoint: SSHSocketEndpoint,
        proxy: SSHConnectionProxy?,
        transportFactory: @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHClientTransportHandle {
        try await self.makeTransportHandle(
            to: endpoint,
            proxy: proxy,
            transportHandleFactory: { endpoint in
                SSHClientTransportHandle(transport: try await transportFactory(endpoint))
            }
        )
    }

    static func makeDefaultTransportHandle(
        to endpoint: SSHSocketEndpoint,
        proxy: SSHConnectionProxy?,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHClientTransportHandle {
        try await self.makeTransportHandle(
            to: endpoint,
            proxy: proxy,
            transportHandleFactory: { endpoint in
                try await SSHTCPByteStreamTransportFactory.makeTransportHandle(
                    to: endpoint,
                    preference: preference
                )
            }
        )
    }

    static func makeDefaultRouteRootTransportHandle(
        to endpoint: SSHSocketEndpoint,
        proxy: SSHConnectionProxy?,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHClientTransportHandle {
        try await self.makeTransportHandle(
            to: endpoint,
            proxy: proxy,
            transportHandleFactory: { endpoint in
                try await SSHTCPByteStreamTransportFactory.makeRouteRootTransportHandle(
                    to: endpoint,
                    preference: preference
                )
            }
        )
    }

    private static func negotiateSOCKS5(
        target: SSHSocketEndpoint,
        proxy: SSHSOCKS5ConnectionProxy,
        transport: SSHBufferedByteStreamTransport
    ) async throws {
        let methods = try self.socks5Methods(for: proxy.authentication)
        try await transport.send(
            [0x05, UInt8(methods.count)] + methods,
            endOfStream: false
        )

        let methodSelection = try await self.readExactByteCount(2, from: transport)
        guard methodSelection[0] == 0x05 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy replied with version \(methodSelection[0]) during method selection."
            )
        }

        switch methodSelection[1] {
        case 0x00:
            guard case .none = proxy.authentication else {
                throw SSHTransportError.proxyHandshakeFailed(
                    "SOCKS5 proxy selected no authentication after username/password was configured."
                )
            }
        case 0x02:
            try await self.authenticateSOCKS5(
                using: proxy.authentication,
                transport: transport
            )
        case 0xff:
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy rejected all advertised authentication methods."
            )
        default:
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy selected unsupported authentication method 0x\(String(methodSelection[1], radix: 16))."
            )
        }

        try await transport.send(
            try self.makeSOCKS5ConnectRequest(target: target),
            endOfStream: false
        )

        let responseHeader = try await self.readExactByteCount(4, from: transport)
        guard responseHeader[0] == 0x05 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy replied with version \(responseHeader[0]) during CONNECT."
            )
        }
        guard responseHeader[2] == 0x00 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy sent a non-zero reserved byte during CONNECT."
            )
        }
        guard responseHeader[1] == 0x00 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 CONNECT failed: \(self.socks5ReplyDescription(responseHeader[1]))."
            )
        }

        try await self.discardSOCKS5Address(
            addressType: responseHeader[3],
            transport: transport
        )
        _ = try await self.readExactByteCount(2, from: transport)
    }

    private static func negotiateHTTPConnect(
        target: SSHSocketEndpoint,
        proxy: SSHHTTPConnectConnectionProxy,
        transport: SSHBufferedByteStreamTransport
    ) async throws {
        let authority = try self.httpConnectAuthority(for: target)
        let request = try self.makeHTTPConnectRequest(
            authority: authority,
            authentication: proxy.authentication
        )

        try await transport.send(Array(request.utf8), endOfStream: false)

        let responseBytes = try await self.readHTTPHeaderBlock(from: transport)
        guard let response = String(bytes: responseBytes, encoding: .utf8) else {
            throw SSHTransportError.proxyHandshakeFailed(
                "HTTP CONNECT proxy returned a non-UTF-8 response header block."
            )
        }

        let lines = response.components(separatedBy: "\r\n")
        guard let statusLine = lines.first, !statusLine.isEmpty else {
            throw SSHTransportError.proxyHandshakeFailed(
                "HTTP CONNECT proxy returned an empty status line."
            )
        }

        let fields = statusLine.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        guard fields.count >= 2,
              let statusCode = Int(fields[1]),
              fields[0].hasPrefix("HTTP/") else {
            throw SSHTransportError.proxyHandshakeFailed(
                "HTTP CONNECT proxy returned an invalid status line: \(statusLine)"
            )
        }

        guard (200...299).contains(statusCode) else {
            throw SSHTransportError.proxyHandshakeFailed(
                "HTTP CONNECT proxy returned status \(statusCode)."
            )
        }
    }

    private static func socks5Methods(
        for authentication: SSHSOCKS5ProxyAuthentication
    ) throws -> [UInt8] {
        _ = try authentication.validatedCredentialBytes {
            SSHTransportError.invalidProxyConfiguration($0)
        }
        return authentication.supportedMethodCodes
    }

    private static func authenticateSOCKS5(
        using authentication: SSHSOCKS5ProxyAuthentication,
        transport: SSHBufferedByteStreamTransport
    ) async throws {
        guard let credentials = try authentication.validatedCredentialBytes(
            invalidConfiguration: { SSHTransportError.invalidProxyConfiguration($0) }
        ) else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy requested username/password authentication, but none was configured."
            )
        }

        try await transport.send(
            [0x01, UInt8(credentials.username.count)] +
                credentials.username +
                [UInt8(credentials.password.count)] +
                credentials.password,
            endOfStream: false
        )

        let response = try await self.readExactByteCount(2, from: transport)
        guard response[0] == 0x01 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy auth replied with unexpected version \(response[0])."
            )
        }
        guard response[1] == 0x00 else {
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 username/password authentication failed with status 0x\(String(response[1], radix: 16))."
            )
        }
    }

    private static func makeSOCKS5ConnectRequest(
        target: SSHSocketEndpoint
    ) throws -> [UInt8] {
        let addressBytes = try self.socks5AddressBytes(for: target.host)
        return [0x05, 0x01, 0x00] +
            addressBytes +
            [UInt8(target.port >> 8), UInt8(target.port & 0xff)]
    }

    private static func socks5AddressBytes(for host: String) throws -> [UInt8] {
        if let ipv4Bytes = self.ipv4AddressBytes(for: host) {
            return [0x01] + ipv4Bytes
        }

        if let ipv6Bytes = self.ipv6AddressBytes(for: host) {
            return [0x04] + ipv6Bytes
        }

        let domainBytes = Array(host.utf8)
        guard !domainBytes.isEmpty else {
            throw SSHTransportError.invalidProxyConfiguration(
                "SOCKS5 target host must not be empty."
            )
        }
        guard domainBytes.count <= 255 else {
            throw SSHTransportError.invalidProxyConfiguration(
                "SOCKS5 target host must fit in 255 UTF-8 bytes."
            )
        }

        return [0x03, UInt8(domainBytes.count)] + domainBytes
    }

    private static func discardSOCKS5Address(
        addressType: UInt8,
        transport: SSHBufferedByteStreamTransport
    ) async throws {
        switch addressType {
        case 0x01:
            _ = try await self.readExactByteCount(4, from: transport)
        case 0x03:
            let length = Int(try await self.readExactByteCount(1, from: transport)[0])
            _ = try await self.readExactByteCount(length, from: transport)
        case 0x04:
            _ = try await self.readExactByteCount(16, from: transport)
        default:
            throw SSHTransportError.proxyHandshakeFailed(
                "SOCKS5 proxy replied with unsupported address type 0x\(String(addressType, radix: 16))."
            )
        }
    }

    private static func socks5ReplyDescription(_ code: UInt8) -> String {
        switch code {
        case 0x01:
            "general SOCKS server failure"
        case 0x02:
            "connection not allowed by ruleset"
        case 0x03:
            "network unreachable"
        case 0x04:
            "host unreachable"
        case 0x05:
            "connection refused"
        case 0x06:
            "TTL expired"
        case 0x07:
            "command not supported"
        case 0x08:
            "address type not supported"
        default:
            "reply code 0x\(String(code, radix: 16))"
        }
    }

    private static func httpConnectAuthority(
        for endpoint: SSHSocketEndpoint
    ) throws -> String {
        guard !endpoint.host.contains("\r"), !endpoint.host.contains("\n") else {
            throw SSHTransportError.invalidProxyConfiguration(
                "HTTP CONNECT target host must not contain CR or LF characters."
            )
        }

        if self.ipv6AddressBytes(for: endpoint.host) != nil {
            return "[\(endpoint.host)]:\(endpoint.port)"
        }

        return "\(endpoint.host):\(endpoint.port)"
    }

    private static func makeHTTPConnectRequest(
        authority: String,
        authentication: SSHHTTPConnectProxyAuthentication
    ) throws -> String {
        var request = "CONNECT \(authority) HTTP/1.1\r\n"
        request += "Host: \(authority)\r\n"

        switch authentication {
        case .none:
            break
        case let .basic(username, password):
            try self.validateHTTPBasicCredentials(username: username, password: password)
            let token = Data("\(username):\(password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }

        request += "\r\n"
        return request
    }

    private static func readHTTPHeaderBlock(
        from transport: SSHBufferedByteStreamTransport
    ) async throws -> [UInt8] {
        var bytes: [UInt8] = []

        while true {
            let byte = try await self.readExactByteCount(1, from: transport)[0]
            bytes.append(byte)

            if bytes.count > self.httpHeaderLimit {
                throw SSHTransportError.proxyHandshakeFailed(
                    "HTTP CONNECT proxy response headers exceeded \(self.httpHeaderLimit) bytes."
                )
            }

            if bytes.count >= 4,
               Array(bytes.suffix(4)) == [0x0d, 0x0a, 0x0d, 0x0a] {
                return bytes
            }
        }
    }

    private static func readExactByteCount(
        _ count: Int,
        from transport: SSHBufferedByteStreamTransport
    ) async throws -> [UInt8] {
        var bytes: [UInt8] = []

        while bytes.count < count {
            let chunk = try await transport.receive(
                atLeast: 1,
                atMost: count - bytes.count
            )
            if chunk.bytes.isEmpty {
                if chunk.endOfStream {
                    throw SSHTransportError.endOfStreamBeforeIdentification
                }
                continue
            }
            bytes += chunk.bytes
        }

        return bytes
    }

    private static func validateHTTPBasicCredentials(
        username: String,
        password: String
    ) throws {
        guard !username.contains(":"), !username.contains("\r"), !username.contains("\n") else {
            throw SSHTransportError.invalidProxyConfiguration(
                "HTTP CONNECT Basic auth usernames must not contain ':', CR, or LF."
            )
        }
        guard !password.contains("\r"), !password.contains("\n") else {
            throw SSHTransportError.invalidProxyConfiguration(
                "HTTP CONNECT Basic auth passwords must not contain CR or LF."
            )
        }
    }

    private static func ipv4AddressBytes(for host: String) -> [UInt8]? {
        var address = in_addr()
        return host.withCString { pointer in
            guard inet_pton(AF_INET, pointer, &address) == 1 else {
                return nil
            }

            return withUnsafeBytes(of: &address) { Array($0) }
        }
    }

    private static func ipv6AddressBytes(for host: String) -> [UInt8]? {
        var address = in6_addr()
        return host.withCString { pointer in
            guard inet_pton(AF_INET6, pointer, &address) == 1 else {
                return nil
            }

            return withUnsafeBytes(of: &address) { Array($0) }
        }
    }
}
