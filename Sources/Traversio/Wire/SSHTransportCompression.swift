// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import TraversioCCrypto

enum SSHTransportCompressionError: Error, Equatable, Sendable {
    case unsupportedCompressionAlgorithm(String)
    case compressionFailed
    case decompressionFailed
}

final class SSHZlibCompressor {
    private let context: OpaquePointer

    init() throws {
        guard let context = traversio_zlib_compressor_new() else {
            throw SSHTransportCompressionError.compressionFailed
        }

        self.context = context
    }

    deinit {
        traversio_zlib_compressor_free(self.context)
    }

    func compress(_ data: [UInt8]) throws -> [UInt8] {
        try Self.process(data) { inputBuffer, outputPointer, outputLength in
            traversio_zlib_compress(
                self.context,
                inputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                data.count,
                outputPointer,
                outputLength
            )
        }
    }
}

final class SSHZlibDecompressor {
    private let context: OpaquePointer

    init() throws {
        guard let context = traversio_zlib_decompressor_new() else {
            throw SSHTransportCompressionError.decompressionFailed
        }

        self.context = context
    }

    deinit {
        traversio_zlib_decompressor_free(self.context)
    }

    func decompress(_ data: [UInt8]) throws -> [UInt8] {
        try SSHZlibCompressor.process(data) { inputBuffer, outputPointer, outputLength in
            traversio_zlib_decompress(
                self.context,
                inputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                data.count,
                outputPointer,
                outputLength
            )
        }
    }
}

struct SSHTransportPayloadCompressor {
    private let algorithmName: String
    private let activatesAfterAuthentication: Bool
    private let compressor: SSHZlibCompressor?
    private(set) var isActive: Bool

    init(
        algorithmName: String,
        authenticationHasCompleted: Bool
    ) throws {
        self.algorithmName = algorithmName

        switch algorithmName {
        case "none":
            self.activatesAfterAuthentication = false
            self.compressor = nil
            self.isActive = false
        case "zlib":
            self.activatesAfterAuthentication = false
            self.compressor = try SSHZlibCompressor()
            self.isActive = true
        case "zlib@openssh.com":
            self.activatesAfterAuthentication = true
            self.compressor = try SSHZlibCompressor()
            self.isActive = authenticationHasCompleted
        default:
            throw SSHTransportCompressionError.unsupportedCompressionAlgorithm(algorithmName)
        }
    }

    mutating func activateIfNeeded() {
        guard self.activatesAfterAuthentication else {
            return
        }

        self.isActive = true
    }

    func compress(_ payload: [UInt8]) throws -> [UInt8] {
        guard self.isActive, let compressor else {
            return payload
        }

        return try compressor.compress(payload)
    }
}

struct SSHTransportPayloadDecompressor {
    private let activatesAfterAuthentication: Bool
    private let decompressor: SSHZlibDecompressor?
    private(set) var isActive: Bool

    init(
        algorithmName: String,
        authenticationHasCompleted: Bool
    ) throws {
        switch algorithmName {
        case "none":
            self.activatesAfterAuthentication = false
            self.decompressor = nil
            self.isActive = false
        case "zlib":
            self.activatesAfterAuthentication = false
            self.decompressor = try SSHZlibDecompressor()
            self.isActive = true
        case "zlib@openssh.com":
            self.activatesAfterAuthentication = true
            self.decompressor = try SSHZlibDecompressor()
            self.isActive = authenticationHasCompleted
        default:
            throw SSHTransportCompressionError.unsupportedCompressionAlgorithm(algorithmName)
        }
    }

    mutating func activateIfNeeded() {
        guard self.activatesAfterAuthentication else {
            return
        }

        self.isActive = true
    }

    func decompress(_ payload: [UInt8]) throws -> [UInt8] {
        guard self.isActive, let decompressor else {
            return payload
        }

        return try decompressor.decompress(payload)
    }
}

extension SSHZlibCompressor {
    fileprivate static func process(
        _ data: [UInt8],
        operation: (
            _ inputBuffer: UnsafeRawBufferPointer,
            _ outputPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
            _ outputLength: UnsafeMutablePointer<Int>
        ) -> Int32
    ) throws -> [UInt8] {
        var outputPointer: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status = data.withUnsafeBytes { inputBuffer in
            withUnsafeMutablePointer(to: &outputPointer) { outputPointerPointer in
                withUnsafeMutablePointer(to: &outputLength) { outputLengthPointer in
                    operation(inputBuffer, outputPointerPointer, outputLengthPointer)
                }
            }
        }

        defer {
            traversio_zlib_buffer_free(outputPointer)
        }

        switch status {
        case TRAVERSIO_ZLIB_SUCCESS:
            guard let outputPointer else {
                return []
            }
            return Array(UnsafeBufferPointer(start: outputPointer, count: outputLength))
        case TRAVERSIO_ZLIB_ERROR_INVALID_DATA:
            throw SSHTransportCompressionError.decompressionFailed
        default:
            throw SSHTransportCompressionError.compressionFailed
        }
    }
}
