//  Copyright (c) 2026 Andrew Beekhof. All rights reserved.
//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// insnrg local patch (NOT upstream amplify-swift code):
//
// amplify-swift 2.63.0 moved the keychain layer out of AWSPluginsCore into
// the new `InternalAmplifyKeychain` module: the protocol is
// `KeychainItemStoreBehavior`, and the SecItem-backed `KeychainItemStore` is
// what every production construction site builds. The stock store lands
// items in the OS Keychain, which is unusable for this project: the
// data-protection Keychain rejects any binary that isn't code-signed with
// the keychain entitlement (errSecMissingEntitlement, OSStatus -34018), and
// the standard (legacy) Keychain prompts for access on every invocation.
//
// This file-backed implementation of the same protocol keeps items as 0600
// files under ~/.insnrg/amplify-keychain/<service>/ on macOS, or the app's
// Application Support directory on iOS, so insnrg never touches the Keychain.
//
// The on-disk layout is byte-for-byte the one the pre-2.63
// FileKeychainStore (scripts/amplify/FileKeychainStore.swift) used, so
// credentials an older insnrg wrote are still readable after an
// amplify-swift bump: one directory per (service, accessGroup) pair, each
// item an `<base64url(key)>.dat` file.
//
// patch-amplify-keychain.sh copies this file into the checkout's
// AmplifyClients/Internal/InternalAmplifyKeychain/Sources/ — next to the
// SecItem store it replaces, so it sees the same `package` symbols — and
// repoints the production `KeychainItemStore(...)` constructions at it
// before every build.

import AmplifyFoundation
import Foundation

/// File-backed `KeychainItemStoreBehavior` — see the note at the top of this file.
///
/// Same storage semantics as the keychain for every protocol member: an
/// absent read throws `KeychainAccessError.itemNotFound`, removing an absent
/// item succeeds, `addIfAbsent` refuses a duplicate (the atomic
/// create-with-existence-check stands in for `SecItemAdd` refusing a
/// duplicate), and `move` reports `.notFound` / `.destinationOccupied`
/// without changing anything. The compare-then-write members are not atomic,
/// for the same reason the keychain's are: there is no compare-and-set.
///
/// - Note: `Sendable` (required by the protocol) because stores are shared
///   across concurrency domains by the auth plugin; the file operations here
///   are atomic renames and the stored properties are immutable.
package struct FileKeychainItemStore: KeychainItemStoreBehavior {
    package let attributes: KeychainItemAttributes
    private let logger: any Logger
    /// One directory per (service, accessGroup) pair, mirroring how the
    /// Keychain namespaces items by (service, access group).
    private let directory: URL

    package init(attributes: KeychainItemAttributes, logger: any Logger) {
        self.attributes = attributes
        self.logger = logger
        self.directory = Self.directory(for: attributes)
        logger.verbose(
            "[FileKeychainItemStore] Initialized file-backed store service=\(attributes.service) "
                + "accessGroup=\(attributes.accessGroup ?? "none") at \(directory.path)"
        )
    }

    package init(
        service: String,
        accessGroup: String? = nil,
        logger: any Logger = AmplifyLogging.logger(for: FileKeychainItemStore.self)
    ) {
        self.init(attributes: KeychainItemAttributes(service: service, accessGroup: accessGroup), logger: logger)
    }

    // MARK: KeychainItemStoreBehavior

    package func getData(_ key: String) throws -> Data {
        let file = self.file(for: key)
        guard FileManager.default.fileExists(atPath: file.path) else {
            logger.verbose("[FileKeychainItemStore] No item found for key=\(key)")
            throw KeychainAccessError.itemNotFound
        }
        do {
            let data = try Data(contentsOf: file)
            logger.verbose("[FileKeychainItemStore] Retrieved item for key=\(key)")
            return data
        } catch {
            logger.error("[FileKeychainItemStore] Failed reading key=\(key) from \(file.path): \(error)")
            throw KeychainAccessError.unknown("Failed reading key=\(key) from \(file.path)", error)
        }
    }

    package func set(_ value: Data, key: String) throws {
        logger.verbose("[FileKeychainItemStore] Setting item for key=\(key)")
        try ensureDirectory()
        try writeFile(value, to: file(for: key))
        logger.verbose("[FileKeychainItemStore] Set item for key=\(key)")
    }

    package func addIfAbsent(_ value: Data, key: String) throws -> Bool {
        try ensureDirectory()
        let file = self.file(for: key)
        // createFile is an atomic create: false means the file exists, which
        // is exactly the `SecItemAdd` refuses-duplicates outcome.
        if FileManager.default.createFile(
            atPath: file.path, contents: value, attributes: [.posixPermissions: 0o600]
        ) {
            return true
        }
        if FileManager.default.fileExists(atPath: file.path) {
            return false
        }
        throw KeychainAccessError.unknown("Unable to add item under \(file.path)")
    }

    package func replaceIfPresent(_ value: Data, key: String) throws -> Bool {
        let file = self.file(for: key)
        guard FileManager.default.fileExists(atPath: file.path) else {
            return false
        }
        do {
            // Rewrite the existing file in place (truncate + write) rather
            // than re-creating it: an item deleted in the meantime stays
            // deleted. Not atomic, as the keychain's update is not.
            let handle = try FileHandle(forWritingTo: file)
            try handle.truncate(atOffset: 0)
            try handle.write(contentsOf: value)
            try handle.close()
            return true
        } catch {
            if !FileManager.default.fileExists(atPath: file.path) {
                return false
            }
            logger.error("[FileKeychainItemStore] Failed replacing key=\(key) at \(file.path): \(error)")
            throw KeychainAccessError.unknown("Failed replacing key=\(key) at \(file.path)", error)
        }
    }

    package func move(_ key: String, to destination: KeychainItemAttributes) throws -> KeychainMoveOutcome {
        try moveItem(from: file(for: key), key: key, to: destination)
    }

    package func move(_ entry: KeychainEntry, to destination: KeychainItemAttributes) throws -> KeychainMoveOutcome {
        // Scoped to the entry's group: the item lives in that group's directory.
        try moveItem(from: file(for: entry.account, groupOverride: entry.accessGroup), key: entry.account, to: destination)
    }

    package func remove(_ key: String) throws {
        try removeItem(file(for: key))
    }

    package func remove(_ entry: KeychainEntry) throws {
        try removeItem(file(for: entry.account, groupOverride: entry.accessGroup))
    }

    package func removeAll() throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: directory.path) else {
            return
        }
        do {
            // Skip temp files (".tmp-…") — a crashed write may leave one.
            let entries = try fm.contentsOfDirectory(atPath: directory.path)
                .filter { !$0.hasPrefix(".") }
            for entry in entries {
                try fm.removeItem(atPath: directory.appendingPathComponent(entry).path)
            }
        } catch {
            logger.error("[FileKeychainItemStore] Failed removing items: \(error)")
            throw KeychainAccessError.unknown("Failed removing all items in \(directory.path)", error)
        }
    }

    package func hasItems() throws -> Bool {
        guard FileManager.default.fileExists(atPath: directory.path) else {
            return false
        }
        do {
            let entries = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            let hasItems = entries.contains { !$0.hasPrefix(".") }
            logger.verbose("[FileKeychainItemStore] Store hasItems=\(hasItems)")
            return hasItems
        } catch {
            throw KeychainAccessError.unknown("Failed listing items in \(directory.path)", error)
        }
    }

    package func allAccounts() throws -> [String] {
        try itemNames().compactMap(Self.decode)
    }

    package func allEntries() throws -> [KeychainEntry] {
        let accounts = try allAccounts()
        return accounts.map { KeychainEntry(account: $0, accessGroup: attributes.accessGroup) }
    }

    // MARK: Private

    private func itemNames() throws -> [String] {
        guard FileManager.default.fileExists(atPath: directory.path) else {
            return []
        }
        do {
            return try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .filter { !$0.hasPrefix(".") && $0.hasSuffix(".dat") }
                .sorted()
        } catch {
            throw KeychainAccessError.unknown("Failed listing items in \(directory.path)", error)
        }
    }

    private func moveItem(from source: URL, key: String, to destination: KeychainItemAttributes) throws -> KeychainMoveOutcome {
        let fm = FileManager.default
        guard fm.fileExists(atPath: source.path) else {
            return .notFound
        }
        let targetDirectory = Self.directory(for: destination)
        let target = targetDirectory.appendingPathComponent(Self.encode(key) + ".dat")
        if fm.fileExists(atPath: target.path) {
            return .destinationOccupied
        }
        do {
            try fm.createDirectory(at: targetDirectory, withIntermediateDirectories: true)
            // rename(2): atomic within the volume, and keeps the 0600 mode.
            try fm.moveItem(at: source, to: target)
            return .moved
        } catch {
            // The pre-checks above are racy; settle on the post-hoc state.
            if fm.fileExists(atPath: target.path) {
                return .destinationOccupied
            }
            if !fm.fileExists(atPath: source.path) {
                return .notFound
            }
            logger.error("[FileKeychainItemStore] Failed moving key=\(key) from \(source.path) to \(target.path): \(error)")
            throw KeychainAccessError.unknown("Failed moving key=\(key) from \(source.path) to \(target.path)", error)
        }
    }

    private func removeItem(_ file: URL) throws {
        guard FileManager.default.fileExists(atPath: file.path) else {
            // Absent item is not an error, matching the keychain's
            // errSecItemNotFound handling.
            return
        }
        do {
            try FileManager.default.removeItem(at: file)
        } catch {
            logger.error("[FileKeychainItemStore] Failed removing \(file.path): \(error)")
            throw KeychainAccessError.unknown("Failed removing \(file.path)", error)
        }
    }

    private func ensureDirectory() throws {
        let fm = FileManager.default
        let base = Self.rootDirectory
        let basePreexisted = fm.fileExists(atPath: base.path)
        do {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            logger.error("[FileKeychainItemStore] Failed creating directory \(directory.path): \(error)")
            throw KeychainAccessError.unknown("Failed creating directory \(directory.path)", error)
        }
        if !basePreexisted {
            // We created the .insnrg root — make the whole thing private.
            try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: base.path)
        }
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.deletingLastPathComponent().path)
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    /// Atomic write: temp file in the same directory, 0600, rename into
    /// place. The rename is atomic within the directory, and the 0700 parent
    /// keeps the temp file unreachable by other users while it briefly
    /// carries the default 0644 mode.
    private func writeFile(_ value: Data, to file: URL) throws {
        let fm = FileManager.default
        let tmp = directory.appendingPathComponent(".tmp-\(UUID().uuidString)")
        do {
            try value.write(to: tmp, options: .atomic)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
            try fm.moveItem(at: tmp, to: file)
        } catch {
            try? fm.removeItem(at: tmp)
            logger.error("[FileKeychainItemStore] Failed writing \(file.path): \(error)")
            throw KeychainAccessError.unknown("Failed writing \(file.path)", error)
        }
    }

    private func file(for key: String, groupOverride: String? = nil) -> URL {
        Self.directory(for: attributes, groupOverride: groupOverride)
            .appendingPathComponent(Self.encode(key) + ".dat")
    }

    /// One directory per (service, accessGroup) pair, matching the Keychain's
    /// (service, access group) item namespace. `groupOverride` scopes a single
    /// entry to another group's directory, as `move(_ entry:to:)` and
    /// `remove(_ entry:)` require.
    private static func directory(for attributes: KeychainItemAttributes, groupOverride: String? = nil) -> URL {
        let group = groupOverride ?? attributes.accessGroup
        let name = group.map { "\(attributes.service)_\($0)" } ?? attributes.service
        return
            rootDirectory
            .appendingPathComponent("amplify-keychain", isDirectory: true)
            .appendingPathComponent(encode(name), isDirectory: true)
    }

    /// On-disk root holding the per-service keychain directories.
    ///
    /// macOS keeps the CLI's existing `~/.insnrg` location so nothing about the
    /// CLI changes; iOS has no per-user home directory, so tokens live under the
    /// app's Application Support directory. The split is compile-time because
    /// `homeDirectoryForCurrentUser` is unavailable on iOS.
    private static var rootDirectory: URL {
        let fm = FileManager.default
        #if os(macOS)
            return fm.homeDirectoryForCurrentUser
                .appendingPathComponent(".insnrg", isDirectory: true)
        #else
            let support =
                (try? fm.url(
                    for: .applicationSupportDirectory,
                    in: .userDomainMask,
                    appropriateFor: nil,
                    create: true
                )) ?? fm.temporaryDirectory
            return support.appendingPathComponent(".insnrg", isDirectory: true)
        #endif
    }

    /// Base64url (no padding) of the string's UTF-8 bytes — maps any
    /// service/key string onto a safe single path component.
    private static func encode(_ s: String) -> String {
        Data(s.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The inverse of `encode(_:)`; `nil` for a name that is not base64url
    /// (a foreign file in the directory, which listings skip).
    private static func decode(_ s: String) -> String? {
        var b64 =
            s
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 {
            b64.append("=")
        }
        guard let data = Data(base64Encoded: b64), let out = String(data: data, encoding: .utf8) else {
            return nil
        }
        return out
    }
}
