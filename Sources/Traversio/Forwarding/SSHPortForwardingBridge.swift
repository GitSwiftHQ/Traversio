// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network
struct SSHPortForwardingBridge: Sendable {
    private static let operationCanceledPOSIXCode = POSIXErrorCode(rawValue: 89)

    let maximumReadSize: Int

    init(maximumReadSize: Int = 4096) {
        self.maximumReadSize = maximumReadSize
    }

    func bridge(
        localTransport: any SSHByteStreamTransport,
        remoteChannel: SSHTCPIPChannelHandle
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await self.pumpLocalToRemote(
                    localTransport: localTransport,
                    remoteChannel: remoteChannel
                )
            }
            group.addTask {
                try await self.pumpRemoteToLocal(
                    remoteChannel: remoteChannel,
                    localTransport: localTransport
                )
            }

            do {
                while try await group.next() != nil {}
                await self.closeRemoteChannelIfNeeded(remoteChannel)
            } catch {
                group.cancelAll()
                await localTransport.close()
                await self.closeRemoteChannelIfNeeded(remoteChannel)
                while let _ = try? await group.next() {}
                guard !Self.shouldIgnoreTerminalCloseError(error) else {
                    return
                }
                throw error
            }
        }
    }

    private func pumpLocalToRemote(
        localTransport: any SSHByteStreamTransport,
        remoteChannel: SSHTCPIPChannelHandle
    ) async throws {
        while true {
            try Task.checkCancellation()
            let chunk = try await localTransport.receive(
                atLeast: 1,
                atMost: self.maximumReadSize
            )
            try Task.checkCancellation()

            if !chunk.bytes.isEmpty {
                try await remoteChannel.write(chunk.bytes)
            }

            if chunk.endOfStream {
                try await remoteChannel.sendEOF()
                return
            }
        }
    }

    private func pumpRemoteToLocal(
        remoteChannel: SSHTCPIPChannelHandle,
        localTransport: any SSHByteStreamTransport
    ) async throws {
        while let event = try await remoteChannel.readEvent(respectCancellation: false) {
            try Task.checkCancellation()

            switch event {
            case let .data(chunk):
                if !chunk.isEmpty {
                    try await localTransport.send(chunk, endOfStream: false)
                }
            case .endOfFile:
                do {
                    try await localTransport.send([], endOfStream: true)
                } catch {
                    guard Self.shouldIgnoreTerminalCloseError(error) else {
                        throw error
                    }
                }
                return
            }
        }

        do {
            try await localTransport.send([], endOfStream: true)
        } catch {
            guard Self.shouldIgnoreTerminalCloseError(error) else {
                throw error
            }
        }
    }

    private func closeRemoteChannelIfNeeded(
        _ remoteChannel: SSHTCPIPChannelHandle
    ) async {
        await remoteChannel.bestEffortCloseIgnoringCancellation()
    }

    private static func shouldIgnoreTerminalCloseError(_ error: any Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let clientError = error as? SSHClientError,
           case let .operationFailed(failure) = clientError,
           failure.code == .channelClosed || failure.code == .transportClosed {
            return true
        }
        if let transportError = error as? SSHTransportError,
           transportError == .endOfStreamBeforePacket {
            return true
        }
        if let networkError = error as? NWError,
           case let .posix(code) = networkError,
           code.rawValue == 89 {
            return true
        }
        if let posixError = error as? POSIXError,
           let operationCanceledPOSIXCode = self.operationCanceledPOSIXCode,
           posixError.code == operationCanceledPOSIXCode {
            return true
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain, nsError.code == 89 {
            return true
        }
        return false
    }
}
