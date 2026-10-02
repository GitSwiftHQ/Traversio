// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Darwin
import Foundation
import Network

enum LoopbackConnectionRefusalTestError: Error {
    case timedOut
}

/// Runs `body` with an IPv4 loopback port that refuses TCP connections.
///
/// The port is released right after the kernel assigns it, so connects to it
/// are refused. A socket that stays bound without listening would not work:
/// Darwin drops a SYN for such a port instead of resetting it. The refusal is
/// checked with a plain BSD connect before `body` runs; a port that another
/// process started listening on in the meantime is replaced. A listener that
/// appears between that check and the connect under test remains possible but
/// is unlikely for a just-released ephemeral port.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func withRefusingLoopbackPort<Result>(
    _ body: (UInt16) async throws -> Result
) async throws -> Result {
    for _ in 0..<5 {
        let port = try releasedLoopbackPort()
        if try loopbackConnectIsRefused(port: port) {
            return try await body(port)
        }
    }
    throw POSIXError(.EADDRINUSE)
}

/// Returns the operation's result, or throws `LoopbackConnectionRefusalTestError.timedOut`
/// when it does not finish within `nanoseconds`.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func withConnectionRefusalTestTimeout<Result: Sendable>(
    nanoseconds: UInt64 = 2_000_000_000,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    try await withThrowingTaskGroup(of: Result.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: nanoseconds)
            throw LoopbackConnectionRefusalTestError.timedOut
        }

        defer {
            group.cancelAll()
        }
        return try await group.next()!
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func isConnectionRefusedError(_ error: any Error) -> Bool {
    if let networkError = error as? NWError,
       case let .posix(code) = networkError {
        return code == .ECONNREFUSED
    }
    return false
}

private func releasedLoopbackPort() throws -> UInt16 {
    let socketDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socketDescriptor >= 0 else {
        throw loopbackRefusalPOSIXError()
    }
    defer {
        Darwin.close(socketDescriptor)
    }

    var address = loopbackAddress(port: 0)
    let bindResult = withUnsafePointer(to: &address) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.bind(
                socketDescriptor,
                socketAddress,
                socklen_t(MemoryLayout<sockaddr_in>.size)
            )
        }
    }
    guard bindResult == 0 else {
        throw loopbackRefusalPOSIXError()
    }

    var boundAddress = sockaddr_in()
    var boundAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameResult = withUnsafeMutablePointer(to: &boundAddress) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.getsockname(socketDescriptor, socketAddress, &boundAddressLength)
        }
    }
    guard nameResult == 0 else {
        throw loopbackRefusalPOSIXError()
    }

    let port = UInt16(bigEndian: boundAddress.sin_port)
    guard port != 0 else {
        throw POSIXError(.EINVAL)
    }
    return port
}

private func loopbackConnectIsRefused(port: UInt16) throws -> Bool {
    let socketDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socketDescriptor >= 0 else {
        throw loopbackRefusalPOSIXError()
    }
    defer {
        Darwin.close(socketDescriptor)
    }

    var address = loopbackAddress(port: port)
    let connectResult = withUnsafePointer(to: &address) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.connect(
                socketDescriptor,
                socketAddress,
                socklen_t(MemoryLayout<sockaddr_in>.size)
            )
        }
    }
    if connectResult == 0 {
        return false
    }
    guard errno == ECONNREFUSED else {
        throw loopbackRefusalPOSIXError()
    }
    return true
}

private func loopbackAddress(port: UInt16) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = in_port_t(port).bigEndian
    address.sin_addr = in_addr(s_addr: UInt32(0x7f00_0001).bigEndian)
    return address
}

private func loopbackRefusalPOSIXError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EINVAL)
}
