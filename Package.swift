// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "securekeystore",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "securekeystore",
            targets: ["securekeystore"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "securekeystore",
            dependencies: [
            ]),
        .testTarget(
            name: "securekeystoreTests",
            dependencies: ["securekeystore"]),
    ]
)
