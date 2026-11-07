//
// Copyright Amazon.com Inc. or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//

import AmplifyFoundation
import Foundation
import XCTest
@testable import InternalAmplifyKeychain

/// `FileKeychainItemStore` writes an item as a temp file in the store directory and moves it into
/// place. The move must *replace* an item that is already there — `FileManager.moveItem` refuses to
/// touch an existing destination (NSCocoaErrorDomain 516 / POSIX EEXIST), which made every `set`
/// after the first throw. These tests drive the real store against the real filesystem (a unique
/// service per run, cleaned up after) so the rename-into-place path is exercised end to end.
final class FileKeychainItemStoreTests: XCTestCase {

    /// A per-run service so the test never collides with items a real client wrote under
    /// `~/.insnrg` (macOS) or Application Support (iOS).
    private let service = "com.insnrg.filekeychain.test.\(UUID().uuidString)"
    private var store: FileKeychainItemStore!

    override func setUp() {
        super.setUp()
        store = FileKeychainItemStore(service: service, logger: SilentLogger())
    }

    override func tearDown() {
        try? store.removeAll()
        store = nil
        super.tearDown()
    }

    /// A `set` replaces the value that was already stored under the key.
    ///
    /// - Given: a value is stored under a key
    /// - When: `set` is called again for the same key
    /// - Then: it does not throw, and the read returns the new value
    ///
    /// This is the exact path that threw "item with the same name already exists" (516 / EEXIST)
    /// when the move could not overwrite the existing `.dat` file.
    func testSetReplacesAnExistingItem() throws {
        let first = Data("first".utf8)
        let second = Data("second".utf8)

        try store.set(first, key: "authConfiguration")
        XCTAssertEqual(try store.getData("authConfiguration"), first)

        try store.set(second, key: "authConfiguration")
        XCTAssertEqual(try store.getData("authConfiguration"), second)
    }

    /// The store is shared across concurrency domains and re-written in flight, so several writers
    /// can target the same item at once (the auth plugin re-stores its configuration repeatedly).
    /// Every writer must win the rename; none may hit an occupied destination.
    ///
    /// - Given: a key written concurrently by several writers, each with its own value
    /// - When: all the sets run
    /// - Then: none throws, and the item holds one of the values written
    func testConcurrentSetsAllSucceed() throws {
        guard let store = self.store else { return }
        let count = 8
        let values = (0..<count).map { Data("value-\($0)".utf8) }
        let errors = FirstError()
        let group = DispatchGroup()

        for value in values {
            group.enter()
            DispatchQueue.global().async {
                do {
                    try store.set(value, key: "authConfiguration")
                } catch {
                    errors.record(error)
                }
                group.leave()
            }
        }
        group.wait()

        XCTAssertNil(errors.value)
        let stored = try store.getData("authConfiguration")
        XCTAssertTrue(values.contains(stored), "expected one of the written values, got \(stored)")
    }
}

/// A lock-guarded box that records the first error written to it. `@unchecked Sendable`:
/// the lock is the synchronization, and the box itself is captured as an immutable reference
/// from the concurrent closures.
private final class FirstError: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Error?

    var value: Error? {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    func record(_ error: Error) {
        lock.lock()
        if _value == nil { _value = error }
        lock.unlock()
    }
}
