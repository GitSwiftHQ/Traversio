// swift-tools-version: 6.2
// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import PackageDescription

let package = Package(
    name: "Traversio",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "Traversio",
            targets: ["Traversio"]
        ),
    ],
    targets: [
        .target(
            name: "TraversioCCrypto",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedLibrary("z")
            ]
        ),
        .target(
            name: "Traversio",
            dependencies: ["TraversioCCrypto"]
        ),
        .testTarget(
            name: "TraversioTests",
            dependencies: ["Traversio"]
        ),
    ]
)
