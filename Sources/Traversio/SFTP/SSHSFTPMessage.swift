// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHSFTPMessageID: UInt8, Equatable, Sendable {
    case initialize = 1
    case openFile = 3
    case close = 4
    case version = 2
    case readFile = 5
    case writeFile = 6
    case lstat = 7
    case fstat = 8
    case setstat = 9
    case fsetstat = 10
    case openDirectory = 11
    case readDirectory = 12
    case removeFile = 13
    case makeDirectory = 14
    case removeDirectory = 15
    case realPath = 16
    case stat = 17
    case rename = 18
    case readLink = 19
    case symbolicLink = 20
    case status = 101
    case handle = 102
    case data = 103
    case name = 104
    case attributes = 105
    case extended = 200
    case extendedReply = 201
}

/// SFTP status code returned by a server.
public struct SSHSFTPStatusCode: RawRepresentable, Equatable, Hashable, Sendable {
    /// Raw Value.
    public let rawValue: UInt32

    /// Creates an SSHSFTPStatusCode.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
/// Ok.

    /// Ok.
    public static let ok = Self(rawValue: 0)
    /// End of File.
    public static let endOfFile = Self(rawValue: 1)
    /// No Such File.
    public static let noSuchFile = Self(rawValue: 2)
    /// Permission Denied.
    public static let permissionDenied = Self(rawValue: 3)
    /// Failure.
    public static let failure = Self(rawValue: 4)
    /// Bad Message.
    public static let badMessage = Self(rawValue: 5)
    /// No Connection.
    public static let noConnection = Self(rawValue: 6)
    /// Connection Lost.
    public static let connectionLost = Self(rawValue: 7)
    /// Operation Unsupported.
    public static let operationUnsupported = Self(rawValue: 8)

    /// Standard Name.
    public var standardName: String? {
        if self == .ok {
            return "SSH_FX_OK"
        }
        if self == .endOfFile {
            return "SSH_FX_EOF"
        }
        if self == .noSuchFile {
            return "SSH_FX_NO_SUCH_FILE"
        }
        if self == .permissionDenied {
            return "SSH_FX_PERMISSION_DENIED"
        }
        if self == .failure {
            return "SSH_FX_FAILURE"
        }
        if self == .badMessage {
            return "SSH_FX_BAD_MESSAGE"
        }
        if self == .noConnection {
            return "SSH_FX_NO_CONNECTION"
        }
        if self == .connectionLost {
            return "SSH_FX_CONNECTION_LOST"
        }
        if self == .operationUnsupported {
            return "SSH_FX_OP_UNSUPPORTED"
        }
        return nil
    }
}

package enum SSHSFTPError: Error, Equatable, Sendable {
    case invalidPacketLength(UInt32)
    case packetTooLarge(length: UInt32, maximum: UInt32)
    case unexpectedMessage(expected: SSHSFTPMessageID, received: SSHSFTPMessageID)
    case unexpectedResponseRequestID(expected: UInt32, received: UInt32)
    case unexpectedResponseWithoutPendingRequest(received: UInt32)
    case unexpectedNameCount(expected: UInt32, received: UInt32)
    case unexpectedDataLength(maximum: UInt32, received: UInt32)
    case unsupportedExtendedRequest(String)
    case status(SSHSFTPStatusMessage)
    case versionExchangeRequired
    case channelClosedBeforePacket
}

/// One extension name and payload advertised by an SFTP server.
public struct SSHSFTPExtension: Equatable, Sendable {
    /// Name.
    public let name: String
    /// Collected channel data.
    public let data: [UInt8]
    /// Creates an SSHSFTPExtension.

    public init(name: String, data: [UInt8]) {
        self.name = name
        self.data = data
    }
}

package struct SSHSFTPInitializeMessage: Equatable, Sendable {
    let version: UInt32
}

package struct SSHSFTPHandle: Equatable, Hashable, Sendable {
    let bytes: [UInt8]
}

/// Open flags used when opening a remote SFTP file.
public struct SSHSFTPOpenFileFlags: OptionSet, Equatable, Hashable, Sendable {
    /// Raw Value.
    public let rawValue: UInt32

    /// Creates an SSHSFTPOpenFileFlags.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
/// Read.

    /// Read.
    public static let read = Self(rawValue: 0x00000001)
    /// Write.
    public static let write = Self(rawValue: 0x00000002)
    /// Append.
    public static let append = Self(rawValue: 0x00000004)
    /// Create.
    public static let create = Self(rawValue: 0x00000008)
    /// Truncate.
    public static let truncate = Self(rawValue: 0x00000010)
    /// Exclusive.
    public static let exclusive = Self(rawValue: 0x00000020)
}

package struct SSHSFTPVersionMessage: Equatable, Sendable {
    let version: UInt32
    let extensions: [SSHSFTPExtension]
}

/// SFTP v3 file attributes.
///
/// Fields are optional because SFTP packets include only the attributes selected
/// by `flags`.
public struct SSHSFTPFileAttributes: Equatable, Sendable {
    /// Size Flag.
    public static let sizeFlag: UInt32 = 0x00000001
    /// User ID And Group ID Flag.
    public static let userIDAndGroupIDFlag: UInt32 = 0x00000002
    /// Permissions Flag.
    public static let permissionsFlag: UInt32 = 0x00000004
    /// Access And Modification Time Flag.
    public static let accessAndModificationTimeFlag: UInt32 = 0x00000008
    /// Extended Flag.
    public static let extendedFlag: UInt32 = 0x80000000
/// Flags.

    /// Flags.
    public let flags: UInt32
    /// Size.
    public let size: UInt64?
    /// User ID.
    public let userID: UInt32?
    /// Group ID.
    public let groupID: UInt32?
    /// Permissions.
    public let permissions: UInt32?
    /// Access Time.
    public let accessTime: UInt32?
    /// Modification Time.
    public let modificationTime: UInt32?
    /// Extensions.
    public let extensions: [SSHSFTPExtension]
    /// Creates an SSHSFTPFileAttributes.

    public init(
        flags: UInt32,
        size: UInt64?,
        userID: UInt32?,
        groupID: UInt32?,
        permissions: UInt32?,
        accessTime: UInt32?,
        modificationTime: UInt32?,
        extensions: [SSHSFTPExtension]
    ) {
        self.flags = flags
        self.size = size
        self.userID = userID
        self.groupID = groupID
        self.permissions = permissions
        self.accessTime = accessTime
        self.modificationTime = modificationTime
        self.extensions = extensions
    }
    /// Empty.

    public static let empty = Self(
        flags: 0,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: nil,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
}

/// Flags returned by OpenSSH `statvfs@openssh.com` and `fstatvfs@openssh.com`.
public struct SSHSFTPFileSystemFlags: OptionSet, Equatable, Hashable, Sendable {
    /// Raw Value.
    public let rawValue: UInt64

    /// Creates an SSHSFTPFileSystemFlags.
    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }
/// Read only.

    /// Read Only.
    public static let readOnly = Self(rawValue: 0x00000001)
    /// No Set User ID.
    public static let noSetUserID = Self(rawValue: 0x00000002)
}

/// Filesystem attributes returned by OpenSSH SFTP VFS extensions.
public struct SSHSFTPFileSystemAttributes: Equatable, Sendable {
    /// Block Size.
    public let blockSize: UInt64
    /// Fundamental Block Size.
    public let fundamentalBlockSize: UInt64
    /// Total Blocks.
    public let totalBlocks: UInt64
    /// Free Blocks.
    public let freeBlocks: UInt64
    /// Available Blocks.
    public let availableBlocks: UInt64
    /// Total File Nodes.
    public let totalFileNodes: UInt64
    /// Free File Nodes.
    public let freeFileNodes: UInt64
    /// Available File Nodes.
    public let availableFileNodes: UInt64
    /// File System ID.
    public let fileSystemID: UInt64
    /// Flags.
    public let flags: SSHSFTPFileSystemFlags
    /// Maximum Filename Length.
    public let maximumFilenameLength: UInt64
    /// Creates an SSHSFTPFileSystemAttributes.

    public init(
        blockSize: UInt64,
        fundamentalBlockSize: UInt64,
        totalBlocks: UInt64,
        freeBlocks: UInt64,
        availableBlocks: UInt64,
        totalFileNodes: UInt64,
        freeFileNodes: UInt64,
        availableFileNodes: UInt64,
        fileSystemID: UInt64,
        flags: SSHSFTPFileSystemFlags,
        maximumFilenameLength: UInt64
    ) {
        self.blockSize = blockSize
        self.fundamentalBlockSize = fundamentalBlockSize
        self.totalBlocks = totalBlocks
        self.freeBlocks = freeBlocks
        self.availableBlocks = availableBlocks
        self.totalFileNodes = totalFileNodes
        self.freeFileNodes = freeFileNodes
        self.availableFileNodes = availableFileNodes
        self.fileSystemID = fileSystemID
        self.flags = flags
        self.maximumFilenameLength = maximumFilenameLength
    }
}

package struct SSHSFTPRealPathMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPOpenFileMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
    let pflags: SSHSFTPOpenFileFlags
    let attributes: SSHSFTPFileAttributes
}

package struct SSHSFTPCloseMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPReadFileMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
    let offset: UInt64
    let length: UInt32
}

package struct SSHSFTPWriteFileMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
    let offset: UInt64
    let data: [UInt8]
}

package struct SSHSFTPLStatMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPFStatMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPSetAttributesMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
    let attributes: SSHSFTPFileAttributes
}

package struct SSHSFTPFSetAttributesMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
    let attributes: SSHSFTPFileAttributes
}

package struct SSHSFTPRemoveFileMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPMakeDirectoryMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
    let attributes: SSHSFTPFileAttributes
}

package struct SSHSFTPRemoveDirectoryMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPOpenDirectoryMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPReadDirectoryMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPStatMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPRenameMessage: Equatable, Sendable {
    let requestID: UInt32
    let oldPath: String
    let newPath: String
}

package struct SSHSFTPPosixRenameMessage: Equatable, Sendable {
    let requestID: UInt32
    let oldPath: String
    let newPath: String
}

package struct SSHSFTPStatVFSMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPFStatVFSMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPFSyncMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPReadLinkMessage: Equatable, Sendable {
    let requestID: UInt32
    let path: String
}

package struct SSHSFTPSymbolicLinkMessage: Equatable, Sendable {
    let requestID: UInt32
    let targetPath: String
    let linkPath: String
}

package struct SSHSFTPStatusMessage: Equatable, Sendable {
    package let requestID: UInt32
    package let statusCode: SSHSFTPStatusCode
    package let errorMessage: String?
    package let languageTag: String?
}

/// One filename entry returned by SFTP `REALPATH`, `READDIR`, or `READLINK`.
public struct SSHSFTPNameEntry: Equatable, Sendable {
    /// Filename.
    public let filename: String
    /// Long Name.
    public let longName: String
    /// Attributes.
    public let attributes: SSHSFTPFileAttributes
    /// Creates an SSHSFTPNameEntry.

    public init(
        filename: String,
        longName: String,
        attributes: SSHSFTPFileAttributes
    ) {
        self.filename = filename
        self.longName = longName
        self.attributes = attributes
    }
}

package struct SSHSFTPNameMessage: Equatable, Sendable {
    let requestID: UInt32
    let entries: [SSHSFTPNameEntry]
}

package struct SSHSFTPHandleMessage: Equatable, Sendable {
    let requestID: UInt32
    let handle: SSHSFTPHandle
}

package struct SSHSFTPDataMessage: Equatable, Sendable {
    let requestID: UInt32
    let data: [UInt8]
}

package struct SSHSFTPAttributesMessage: Equatable, Sendable {
    let requestID: UInt32
    let attributes: SSHSFTPFileAttributes
}

package struct SSHSFTPExtendedReplyMessage: Equatable, Sendable {
    let requestID: UInt32
    let data: [UInt8]
}

package enum SSHSFTPMessage: Equatable, Sendable {
    case initialize(SSHSFTPInitializeMessage)
    case openFile(SSHSFTPOpenFileMessage)
    case close(SSHSFTPCloseMessage)
    case version(SSHSFTPVersionMessage)
    case readFile(SSHSFTPReadFileMessage)
    case writeFile(SSHSFTPWriteFileMessage)
    case lstat(SSHSFTPLStatMessage)
    case fstat(SSHSFTPFStatMessage)
    case setAttributes(SSHSFTPSetAttributesMessage)
    case fsetAttributes(SSHSFTPFSetAttributesMessage)
    case removeFile(SSHSFTPRemoveFileMessage)
    case makeDirectory(SSHSFTPMakeDirectoryMessage)
    case removeDirectory(SSHSFTPRemoveDirectoryMessage)
    case openDirectory(SSHSFTPOpenDirectoryMessage)
    case readDirectory(SSHSFTPReadDirectoryMessage)
    case realPath(SSHSFTPRealPathMessage)
    case stat(SSHSFTPStatMessage)
    case rename(SSHSFTPRenameMessage)
    case posixRename(SSHSFTPPosixRenameMessage)
    case statVFS(SSHSFTPStatVFSMessage)
    case fstatVFS(SSHSFTPFStatVFSMessage)
    case fsync(SSHSFTPFSyncMessage)
    case readLink(SSHSFTPReadLinkMessage)
    case symbolicLink(SSHSFTPSymbolicLinkMessage)
    case status(SSHSFTPStatusMessage)
    case handle(SSHSFTPHandleMessage)
    case data(SSHSFTPDataMessage)
    case name(SSHSFTPNameMessage)
    case attributes(SSHSFTPAttributesMessage)
    case extendedReply(SSHSFTPExtendedReplyMessage)

    var messageID: SSHSFTPMessageID {
        switch self {
        case .initialize:
            return .initialize
        case .openFile:
            return .openFile
        case .close:
            return .close
        case .version:
            return .version
        case .readFile:
            return .readFile
        case .writeFile:
            return .writeFile
        case .lstat:
            return .lstat
        case .fstat:
            return .fstat
        case .setAttributes:
            return .setstat
        case .fsetAttributes:
            return .fsetstat
        case .removeFile:
            return .removeFile
        case .makeDirectory:
            return .makeDirectory
        case .removeDirectory:
            return .removeDirectory
        case .openDirectory:
            return .openDirectory
        case .readDirectory:
            return .readDirectory
        case .realPath:
            return .realPath
        case .stat:
            return .stat
        case .rename:
            return .rename
        case .posixRename:
            return .extended
        case .statVFS:
            return .extended
        case .fstatVFS:
            return .extended
        case .fsync:
            return .extended
        case .readLink:
            return .readLink
        case .symbolicLink:
            return .symbolicLink
        case .status:
            return .status
        case .handle:
            return .handle
        case .data:
            return .data
        case .name:
            return .name
        case .attributes:
            return .attributes
        case .extendedReply:
            return .extendedReply
        }
    }

    var responseRequestID: UInt32? {
        switch self {
        case let .status(message):
            return message.requestID
        case let .handle(message):
            return message.requestID
        case let .data(message):
            return message.requestID
        case let .name(message):
            return message.requestID
        case let .attributes(message):
            return message.requestID
        case let .extendedReply(message):
            return message.requestID
        default:
            return nil
        }
    }
}

/// SFTP version and extension information negotiated at subsystem startup.
public struct SSHSFTPVersionExchange: Equatable, Sendable {
    /// Client Version.
    public let clientVersion: UInt32
    /// Server Version.
    public let serverVersion: UInt32
    /// Extensions.
    public let extensions: [SSHSFTPExtension]

    /// Returns extension payload data by extension name.
    public func extensionData(named name: String) -> SSHSFTPExtension? {
        self.extensions.first { $0.name == name }
    }

    /// Returns whether the server advertised an extension, optionally requiring
    /// a numeric minimum version encoded as UTF-8 decimal bytes.
    public func supportsExtension(named name: String, minimumVersion: UInt32? = nil) -> Bool {
        guard let advertisedExtension = self.extensionData(named: name) else {
            return false
        }
        guard let minimumVersion else {
            return true
        }

        let versionString = String(decoding: advertisedExtension.data, as: UTF8.self)
        guard let advertisedVersion = UInt32(versionString) else {
            return false
        }
        return advertisedVersion >= minimumVersion
    }
}
