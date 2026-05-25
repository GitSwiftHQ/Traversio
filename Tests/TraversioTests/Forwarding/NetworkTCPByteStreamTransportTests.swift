// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network
import Testing
@testable import Traversio

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportCloseReturnsPromptlyWhilePeerStaysOpen() async throws {
    let server = try await HangingPeerTCPServer.start()
    defer {
        server.stop()
    }

    let transport = try NetworkTCPByteStreamTransport.connect(
        to: SSHSocketEndpoint(host: "127.0.0.1", port: server.port)
    )
    try await transport.send(Array("PING".utf8), endOfStream: false)
    await server.waitForAcceptedConnection()

    let closeTask = Task {
        await transport.close()
        return true
    }

    let didFinishClose = await withTaskGroup(of: Bool.self) { group in
        group.addTask {
            await closeTask.value
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            return false
        }

        let firstResult = await group.next() ?? false
        group.cancelAll()
        return firstResult
    }

    #expect(didFinishClose)
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportCloseStateClaimsEndOfStreamOnce() {
    let closeState = NetworkTCPByteStreamTransport.CloseState()

    #expect(closeState.claimEndOfStreamSend())
    #expect(!closeState.claimEndOfStreamSend())
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportReleasesConnectionOnClose() async throws {
    let transport = try NetworkTCPByteStreamTransport.connect(
        to: SSHSocketEndpoint(host: "127.0.0.1", port: 9)
    )

    await transport.close()
    await transport.close()
    await transport.setObservationHandler(nil)

    do {
        try await transport.send(Array("PING".utf8), endOfStream: false)
        Issue.record("Expected send after close to fail")
    } catch {
        #expect(error as? SSHTransportError == .transportClosed)
    }

    do {
        _ = try await transport.receive(atLeast: 1, atMost: 4)
        Issue.record("Expected receive after close to fail")
    } catch {
        #expect(error as? SSHTransportError == .transportClosed)
    }
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportRecognizesScopedOperationCanceledErrors() throws {
    let operationCanceled = try #require(POSIXErrorCode(rawValue: 89))

    #expect(
        NetworkTCPByteStreamTransport.isExpectedScopedCloseError(
            NWError.posix(operationCanceled)
        )
    )
    #expect(
        NetworkTCPByteStreamTransport.isExpectedScopedCloseError(
            POSIXError(operationCanceled)
        )
    )
    #expect(
        NetworkTCPByteStreamTransport.isExpectedScopedCloseError(
            NSError(domain: NSPOSIXErrorDomain, code: 89)
        )
    )
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportDoesNotTreatOtherErrorsAsScopedCloseErrors() throws {
    #expect(
        !NetworkTCPByteStreamTransport.isExpectedScopedCloseError(
            NSError(domain: NSPOSIXErrorDomain, code: 61)
        )
    )
    #expect(
        !NetworkTCPByteStreamTransport.isExpectedScopedCloseError(
            NSError(domain: NSCocoaErrorDomain, code: 1)
        )
    )
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
@Test
func networkTCPByteStreamTransportFailsWhenScopedConnectionProducesNoResult() throws {
    do {
        _ = try NetworkTCPByteStreamTransport.requireScopedResult(
            Optional<Int>.none,
            endpoint: SSHSocketEndpoint(host: "example.com", port: 22)
        )
        Issue.record("Expected missing scoped result to surface as an invariant error")
    } catch {
        #expect(
            error as? SSHTransportError
                == .internalInvariantBroken(
                    "withNetworkConnection completed without producing a result for example.com:22"
                )
        )
    }
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 1.0, *)
@Test
func remotePortForwardListenerRecognizesExpectedShutdownErrors() throws {
    let operationCanceled = try #require(POSIXErrorCode(rawValue: 89))

    #expect(
        SSHRemotePortForwardListenerService.isExpectedShutdownError(
            NWError.posix(operationCanceled)
        )
    )
    #expect(
        SSHRemotePortForwardListenerService.isExpectedShutdownError(
            POSIXError(operationCanceled)
        )
    )
    #expect(
        SSHRemotePortForwardListenerService.isExpectedShutdownError(
            NSError(domain: NSPOSIXErrorDomain, code: 89)
        )
    )
    #expect(
        !SSHRemotePortForwardListenerService.isExpectedShutdownError(
            NSError(domain: NSPOSIXErrorDomain, code: 61)
        )
    )
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 1.0, *)
@Test
func remotePortForwardListenerTreatsOperationCanceledTransportErrorsAsShutdownLivenessFailures() throws {
    let operationCanceled = try #require(POSIXErrorCode(rawValue: 89))

    #expect(
        SSHRemotePortForwardListenerService.isShutdownLivenessFailure(
            NWError.posix(operationCanceled)
        )
    )
    #expect(
        SSHRemotePortForwardListenerService.isShutdownLivenessFailure(
            POSIXError(operationCanceled)
        )
    )
    #expect(
        SSHRemotePortForwardListenerService.isShutdownLivenessFailure(
            NSError(domain: NSPOSIXErrorDomain, code: 89)
        )
    )
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 1.0, *)
@Test
func remotePortForwardListenerClosesConnectionWhenCancelRequestIsRejected() {
    #expect(
        SSHRemotePortForwardListenerService.requiresConnectionClosureAfterShutdownFailure(
            SSHConnectionError.globalRequestFailed(requestType: "cancel-tcpip-forward")
        )
    )
    #expect(
        !SSHRemotePortForwardListenerService.requiresConnectionClosureAfterShutdownFailure(
            SSHConnectionError.globalRequestFailed(requestType: "tcpip-forward")
        )
    )
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
private final class HangingPeerTCPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue: DispatchQueue
    private let acceptedConnectionState = HangingPeerTCPServerOneShot<Void>()
    private let acceptedConnectionLock = NSLock()
    private var acceptedConnection: NWConnection?

    private(set) var port: UInt16 = 0

    private init(listener: NWListener) {
        self.listener = listener
        self.queue = DispatchQueue(
            label: "Traversio.HangingPeerTCPServer.\(UUID().uuidString)"
        )
    }

    static func start() async throws -> HangingPeerTCPServer {
        let listener = try NWListener(using: .tcp, on: .any)
        let readyState = HangingPeerTCPServerOneShot<UInt16>()
        let server = HangingPeerTCPServer(listener: listener)

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port?.rawValue {
                    readyState.resume(with: .success(port))
                }
            case let .failed(error):
                readyState.resume(with: .failure(error))
            case .cancelled:
                readyState.resume(with: .failure(CancellationError()))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }

        listener.newConnectionHandler = { [server] connection in
            server.storeAcceptedConnection(connection)
            server.acceptedConnectionState.resume(with: .success(()))
            connection.start(queue: server.queue)
        }

        listener.start(queue: server.queue)
        server.port = try await readyState.value()
        return server
    }

    func waitForAcceptedConnection() async {
        _ = try? await self.acceptedConnectionState.value()
    }

    func stop() {
        self.acceptedConnectionLock.lock()
        let acceptedConnection = self.acceptedConnection
        self.acceptedConnection = nil
        self.acceptedConnectionLock.unlock()

        acceptedConnection?.stateUpdateHandler = nil
        acceptedConnection?.cancel()
        self.listener.stateUpdateHandler = nil
        self.listener.newConnectionHandler = nil
        self.listener.cancel()
    }

    private func storeAcceptedConnection(_ connection: NWConnection) {
        self.acceptedConnectionLock.lock()
        self.acceptedConnection = connection
        self.acceptedConnectionLock.unlock()
    }
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
private final class HangingPeerTCPServerOneShot<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var result: Result<Value, Error>?
    private var didResume = false

    func value() async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            self.install(continuation)
        }
    }

    func install(_ continuation: CheckedContinuation<Value, Error>) {
        let result: Result<Value, Error>?

        self.lock.lock()
        if self.didResume {
            result = self.result
        } else {
            self.continuation = continuation
            result = nil
        }
        self.lock.unlock()

        guard let result else {
            return
        }

        continuation.resume(with: result)
    }

    @discardableResult
    func resume(with result: Result<Value, Error>) -> Bool {
        let continuation: CheckedContinuation<Value, Error>?

        self.lock.lock()
        guard !self.didResume else {
            self.lock.unlock()
            return false
        }

        self.didResume = true
        self.result = result
        continuation = self.continuation
        self.continuation = nil
        self.lock.unlock()

        continuation?.resume(with: result)
        return true
    }
}
