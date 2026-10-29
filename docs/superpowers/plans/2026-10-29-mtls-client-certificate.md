# mTLS Client Certificate Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-server PKCS#12 client-certificate authentication to the AudioBooth iOS and watchOS apps.

**Architecture:** Store one PKCS#12 identity per server connection in the Keychain. A shared session provider attaches a client-certificate challenge handler to API, image, download, and direct-file sessions. The iPhone syncs the identity to the watch over WatchConnectivity.

**Tech Stack:** Swift 6.2, SwiftUI, Swift Concurrency, Security framework (`SecPKCS12Import`), SimpleKeychain, Pulse `URLSessionProxy`, Nuke `DataLoader`, WatchConnectivity.

**Spec:** `docs/superpowers/specs/2026-10-29-mtls-client-certificate-design.md`

## Global Constraints

- Swift 6.2, iOS 17.0+, watchOS 10.0+.
- Do not add third-party dependencies. Use SimpleKeychain, Pulse, and Nuke.
- Store PKCS#12 data and password only in the Keychain. Never put them in `Connection`, `UserDefaults`, logs, analytics, or crash reports.
- Present a certificate only for the primary and alternative server endpoints.
- Keep normal server-certificate validation unchanged. Do not add a trust override.
- Document that OIDC system-browser sign-in needs a system-installed certificate profile.
- Do not add code comments.
- Run `swift-format format --in-place` and `swift-format lint --strict` on changed Swift files.
- Work on branch `feature/mtls-client-certificate`.

## Review Focus

1. Wrong password or malformed `.p12` must show a clear error and store nothing.
2. A server that requires a certificate with none configured must show a certificate-specific error, not a generic network error.
3. A certificate must never be sent to an unrelated host after a redirect.
4. Replacing or removing a certificate must delete the old Keychain item and invalidate cached sessions.
5. A watch that lost its certificate after a reinstall must request a resend and show a clear download error if the resend fails.

---

### Task 1: Certificate model and connection persistence

**Files:**
- Create: `API/Sources/API/Models/ClientCertificate.swift`
- Create: `API/Sources/API/Models/ClientCertificateEndpoint.swift`
- Modify: `API/Sources/API/Models/Connection.swift`
- Modify: `API/Sources/API/Models/Server.swift`
- Modify: `API/Package.swift`
- Test: `API/Tests/APITests/ClientCertificateReferenceTests.swift`

**Interfaces:**
- Consumes: existing `Connection`, `Server`, and `Credentials` models.
- Produces: `ClientCertificateReference`, `StoredClientCertificate`, `ClientCertificateEndpoint`, `Server.clientCertificate`, `Server.certificateAllowedHosts`.

- [ ] **Step 1: Add the API test target**

Add this target to `API/Package.swift`:

```swift
.testTarget(
  name: "APITests",
  dependencies: ["API"]
)
```

- [ ] **Step 2: Write the failing tests**

Create `API/Tests/APITests/ClientCertificateReferenceTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateReferenceTests: XCTestCase {
  func testConnectionDecodesWithoutClientCertificate() throws {
    let json = """
    {"id":"server-1","serverURL":"https://example.com","token":"legacy-token","customHeaders":{}}
    """.data(using: .utf8)!

    let connection = try JSONDecoder().decode(Connection.self, from: json)

    XCTAssertNil(connection.clientCertificate)
  }

  func testConnectionRoundTripsClientCertificate() throws {
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date(timeIntervalSince1970: 1_700_000_000)
    )
    let connection = Connection(
      id: "server-1",
      serverURL: URL(string: "https://example.com")!,
      token: .legacy(token: "legacy-token"),
      clientCertificate: reference
    )

    let decoded = try JSONDecoder().decode(
      Connection.self,
      from: JSONEncoder().encode(connection)
    )

    XCTAssertEqual(decoded.clientCertificate, reference)
  }

  func testEndpointUsesDefaultHTTPSPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "https://Example.com")!)

    XCTAssertEqual(endpoint?.key, "example.com:443")
  }

  func testEndpointUsesExplicitPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "https://alt.example.com:8443")!)

    XCTAssertEqual(endpoint?.key, "alt.example.com:8443")
  }

  func testEndpointUsesDefaultHTTPPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "http://example.com")!)

    XCTAssertEqual(endpoint?.key, "example.com:80")
  }

  @MainActor
  func testServerAllowedHostsIncludePrimaryAndAlternative() {
    let connection = Connection(
      serverURL: URL(string: "https://Example.com")!,
      token: .legacy(token: "legacy-token"),
      alternativeURL: URL(string: "https://alt.example.com:8443")!
    )

    let server = Server(connection: connection)

    XCTAssertEqual(server.certificateAllowedHosts, ["example.com:443", "alt.example.com:8443"])
  }
}
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateReference` and `ClientCertificateEndpoint` do not exist.

- [ ] **Step 4: Implement the model and persistence changes**

Create `API/Sources/API/Models/ClientCertificate.swift`:

```swift
import Foundation

public struct ClientCertificateReference: Codable, Sendable, Equatable {
  public let id: String
  public let displayName: String
  public let fingerprintSHA256: String
  public let importedAt: Date

  public init(
    id: String,
    displayName: String,
    fingerprintSHA256: String,
    importedAt: Date
  ) {
    self.id = id
    self.displayName = displayName
    self.fingerprintSHA256 = fingerprintSHA256
    self.importedAt = importedAt
  }
}

public struct StoredClientCertificate: Codable, Sendable {
  public let reference: ClientCertificateReference
  public let p12Data: Data
  public let password: String

  public init(
    reference: ClientCertificateReference,
    p12Data: Data,
    password: String
  ) {
    self.reference = reference
    self.p12Data = p12Data
    self.password = password
  }
}
```

Create `API/Sources/API/Models/ClientCertificateEndpoint.swift`:

```swift
import Foundation

public struct ClientCertificateEndpoint: Hashable, Sendable {
  public let key: String

  public init?(url: URL) {
    guard let host = url.host else { return nil }
    let defaultPort = url.scheme?.lowercased() == "http" ? 80 : 443
    self.init(host: host, port: url.port ?? defaultPort)
  }

  public init?(host: String, port: Int) {
    guard !host.isEmpty, port > 0 else { return nil }
    self.key = "\(host.lowercased()):\(port)"
  }
}
```

Modify `Connection`:

```swift
public let clientCertificate: ClientCertificateReference?

public init(
  id: String? = nil,
  serverURL: URL,
  token: Credentials,
  customHeaders: [String: String] = [:],
  alias: String? = nil,
  alternativeURL: URL? = nil,
  isUsingAlternativeURL: Bool = false,
  clientCertificate: ClientCertificateReference? = nil
) {
  self.clientCertificate = clientCertificate
  // keep existing assignments
}
```

Add `clientCertificate` to `init(_ server:)` and decode it in `init(from:)` with `decodeIfPresent`.

Modify `Server`:

```swift
public internal(set) var clientCertificate: ClientCertificateReference?

public var certificateAllowedHosts: Set<String> {
  var hosts: Set<String> = []
  if let endpoint = ClientCertificateEndpoint(url: baseURL) {
    hosts.insert(endpoint.key)
  }
  if let alternativeURL, let endpoint = ClientCertificateEndpoint(url: alternativeURL) {
    hosts.insert(endpoint.key)
  }
  return hosts
}
```

Set `self.clientCertificate = connection.clientCertificate` in `Server.init(connection:)`.

- [ ] **Step 5: Run the tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for `ClientCertificateReferenceTests`.

- [ ] **Step 6: Commit**

```bash
git add API/Package.swift API/Sources/API/Models/ClientCertificate.swift \
  API/Sources/API/Models/ClientCertificateEndpoint.swift \
  API/Sources/API/Models/Connection.swift API/Sources/API/Models/Server.swift \
  API/Tests/APITests/ClientCertificateReferenceTests.swift
git commit -m "Add client certificate model and connection storage"
```

---

### Task 2: PKCS#12 importer

**Files:**
- Create: `API/Sources/API/Services/ClientCertificateImporter.swift`
- Create: `API/Tests/APITests/Fixtures/client.p12`
- Create: `API/Tests/APITests/Fixtures/client-cert-only.p12`
- Modify: `API/Package.swift`
- Test: `API/Tests/APITests/ClientCertificateImporterTests.swift`

**Interfaces:**
- Consumes: `ClientCertificateReference`, `StoredClientCertificate`.
- Produces: `ClientCertificateImporter.importPKCS12(data:password:displayName:)`, `ClientCertificateImportError`.

- [ ] **Step 1: Generate the test fixtures**

Run in `API/Tests/APITests/Fixtures`:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 3650 -nodes -subj "/CN=AudioBooth Test Client"
openssl pkcs12 -export -out client.p12 -inkey key.pem -in cert.pem -passout pass:test
openssl pkcs12 -export -nokeys -in cert.pem -out client-cert-only.p12 -passout pass:test
rm key.pem cert.pem
```

Add this resource rule to the `APITests` target:

```swift
resources: [.copy("Fixtures")]
```

- [ ] **Step 2: Write the failing tests**

Create `API/Tests/APITests/ClientCertificateImporterTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateImporterTests: XCTestCase {
  private func fixture(_ name: String) throws -> Data {
    let url = try XCTUnwrap(
      Bundle.module.url(
        forResource: name,
        withExtension: "p12",
        subdirectory: "Fixtures"
      )
    )
    return try Data(contentsOf: url)
  }

  func testImportsValidPKCS12() throws {
    let stored = try ClientCertificateImporter.importPKCS12(
      data: fixture("client"),
      password: "test",
      displayName: "client"
    )

    XCTAssertEqual(stored.reference.displayName, "client")
    XCTAssertEqual(stored.reference.fingerprintSHA256.count, 64)
    XCTAssertEqual(
      stored.reference.fingerprintSHA256,
      stored.reference.fingerprintSHA256.lowercased()
    )
    XCTAssertEqual(stored.p12Data, try fixture("client"))
  }

  func testRejectsWrongPassword() throws {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: fixture("client"),
        password: "wrong",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .wrongPassword)
    }
  }

  func testRejectsInvalidData() {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: Data("not a p12".utf8),
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .invalidFormat)
    }
  }

  func testRejectsOversizedData() {
    let data = Data(count: ClientCertificateImporter.maximumFileSize + 1)

    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: data,
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .tooLarge)
    }
  }

  func testRejectsPKCS12WithoutIdentity() throws {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: fixture("client-cert-only"),
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .missingIdentity)
    }
  }
}
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateImporter` does not exist.

- [ ] **Step 4: Implement the importer**

Create `API/Sources/API/Services/ClientCertificateImporter.swift`:

```swift
import CryptoKit
import Foundation
import Security

public enum ClientCertificateImportError: LocalizedError, Equatable {
  case tooLarge
  case invalidFormat
  case wrongPassword
  case missingIdentity

  public var errorDescription: String? {
    switch self {
    case .tooLarge:
      return "The certificate file is too large."
    case .invalidFormat:
      return "The certificate file is not a supported PKCS#12 file."
    case .wrongPassword:
      return "The certificate password is incorrect."
    case .missingIdentity:
      return "The certificate file does not contain a private key."
    }
  }
}

public enum ClientCertificateImporter {
  public static let maximumFileSize = 1_048_576

  public static func importPKCS12(
    data: Data,
    password: String,
    displayName: String
  ) throws -> StoredClientCertificate {
    guard data.count <= maximumFileSize else {
      throw ClientCertificateImportError.tooLarge
    }

    let options = [kSecImportExportPassphrase as String: password]
    var items: CFArray?
    let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)

    switch status {
    case errSecSuccess:
      break
    case errSecAuthFailed, errSecPkcs12VerifyFailure:
      throw ClientCertificateImportError.wrongPassword
    default:
      throw ClientCertificateImportError.invalidFormat
    }

    guard
      let entries = items as? [[String: Any]],
      let entry = entries.first,
      let identity = entry[kSecImportItemIdentity as String] as? SecIdentity
    else {
      throw ClientCertificateImportError.missingIdentity
    }

    var certificate: SecCertificate?
    guard
      SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      let certificate
    else {
      throw ClientCertificateImportError.missingIdentity
    }

    let certificateData = SecCertificateCopyData(certificate) as Data
    let fingerprint = SHA256.hash(data: certificateData)
      .map { String(format: "%02x", $0) }
      .joined()

    let resolvedName =
      displayName.isEmpty
      ? (SecCertificateCopySubjectSummary(certificate) as String? ?? "Client Certificate")
      : displayName

    let reference = ClientCertificateReference(
      id: UUID().uuidString,
      displayName: resolvedName,
      fingerprintSHA256: fingerprint,
      importedAt: Date()
    )

    return StoredClientCertificate(
      reference: reference,
      p12Data: data,
      password: password
    )
  }
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for `ClientCertificateImporterTests`.

- [ ] **Step 6: Commit**

```bash
git add API/Package.swift API/Sources/API/Services/ClientCertificateImporter.swift \
  API/Tests/APITests/ClientCertificateImporterTests.swift \
  API/Tests/APITests/Fixtures/client.p12 \
  API/Tests/APITests/Fixtures/client-cert-only.p12
git commit -m "Add PKCS12 client certificate importer"
```

---

### Task 3: Keychain store and import coordinator

**Files:**
- Create: `API/Sources/API/Services/ClientCertificateStore.swift`
- Create: `API/Sources/API/Services/ClientCertificateImportCoordinator.swift`
- Test: `API/Tests/APITests/ClientCertificateStoreTests.swift`
- Test: `API/Tests/APITests/ClientCertificateImportCoordinatorTests.swift`

**Interfaces:**
- Consumes: `StoredClientCertificate`, `ClientCertificateImporter`.
- Produces: `ClientCertificateStoring`, `ClientCertificateStore`, `PendingClientCertificateImport`, `ClientCertificateImportCoordinator`.

- [ ] **Step 1: Write the failing store tests**

Create `API/Tests/APITests/ClientCertificateStoreTests.swift`:

```swift
import XCTest
@testable import API

final class InMemoryClientCertificateKeychain: ClientCertificateKeychain {
  var storage: [String: Data] = [:]

  func set(_ data: Data, forKey key: String) throws {
    storage[key] = data
  }

  func data(forKey key: String) throws -> Data? {
    storage[key]
  }

  func delete(forKey key: String) throws {
    storage.removeValue(forKey: key)
  }
}

final class ClientCertificateStoreTests: XCTestCase {
  private func makeCertificate(id: String = "cert-1") -> StoredClientCertificate {
    StoredClientCertificate(
      reference: ClientCertificateReference(
        id: id,
        displayName: "client",
        fingerprintSHA256: String(repeating: "a", count: 64),
        importedAt: Date(timeIntervalSince1970: 1_700_000_000)
      ),
      p12Data: Data([1, 2, 3]),
      password: "test"
    )
  }

  func testSaveLoadAndDelete() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)
    let certificate = makeCertificate()

    try store.save(certificate)

    XCTAssertEqual(store.load(id: "cert-1")?.reference, certificate.reference)
    XCTAssertEqual(store.load(id: "cert-1")?.p12Data, certificate.p12Data)

    store.delete(id: "cert-1")

    XCTAssertNil(store.load(id: "cert-1"))
  }

  func testSaveOverwritesExistingItem() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)

    try store.save(makeCertificate(id: "cert-1"))

    let replacement = StoredClientCertificate(
      reference: ClientCertificateReference(
        id: "cert-1",
        displayName: "replacement",
        fingerprintSHA256: String(repeating: "b", count: 64),
        importedAt: Date()
      ),
      p12Data: Data([4, 5, 6]),
      password: "new"
    )
    try store.save(replacement)

    XCTAssertEqual(store.load(id: "cert-1")?.reference.displayName, "replacement")
  }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateKeychain` and `ClientCertificateStore` do not exist.

- [ ] **Step 3: Implement the store**

Create `API/Sources/API/Services/ClientCertificateStore.swift` with:

```swift
protocol ClientCertificateKeychain: Sendable {
  func set(_ data: Data, forKey key: String) throws
  func data(forKey key: String) throws -> Data?
  func delete(forKey key: String) throws
}

public protocol ClientCertificateStoring: Sendable {
  func save(_ certificate: StoredClientCertificate) throws
  func load(id: String) -> StoredClientCertificate?
  func delete(id: String)
}

struct SimpleKeychainBackend: ClientCertificateKeychain {
  private let keychain = SimpleKeychain(
    service: "me.jgrenier.AudioBS.client-certificate",
    accessibility: .afterFirstUnlockThisDeviceOnly
  )

  func set(_ data: Data, forKey key: String) throws {
    try keychain.set(data, forKey: key)
  }

  func data(forKey key: String) throws -> Data? {
    try? keychain.data(forKey: key)
  }

  func delete(forKey key: String) throws {
    try? keychain.deleteItem(forKey: key)
  }
}

public final class ClientCertificateStore: ClientCertificateStoring, @unchecked Sendable {
  public static let shared = ClientCertificateStore()

  private let keychain: any ClientCertificateKeychain
  private let lock = NSLock()
  private let encoder = JSONEncoder()
  private let decoder = JSONDecoder()

  init(keychain: any ClientCertificateKeychain = SimpleKeychainBackend()) {
    self.keychain = keychain
  }

  public func save(_ certificate: StoredClientCertificate) throws {
    lock.lock()
    defer { lock.unlock() }
    try keychain.set(try encoder.encode(certificate), forKey: certificate.reference.id)
  }

  public func load(id: String) -> StoredClientCertificate? {
    lock.lock()
    defer { lock.unlock() }
    guard let data = try? keychain.data(forKey: id) else { return nil }
    return try? decoder.decode(StoredClientCertificate.self, from: data)
  }

  public func delete(id: String) {
    lock.lock()
    defer { lock.unlock() }
    try? keychain.delete(forKey: id)
  }
}
```

Add `import SimpleKeychain`.

- [ ] **Step 4: Run the store tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for `ClientCertificateStoreTests`.

- [ ] **Step 5: Write the failing coordinator tests**

Create `API/Tests/APITests/ClientCertificateImportCoordinatorTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateImportCoordinatorTests: XCTestCase {
  private final class FakeStore: ClientCertificateStoring, @unchecked Sendable {
    var saved: StoredClientCertificate?

    func save(_ certificate: StoredClientCertificate) throws {
      saved = certificate
    }

    func load(id: String) -> StoredClientCertificate? {
      saved?.reference.id == id ? saved : nil
    }

    func delete(id: String) {
      if saved?.reference.id == id {
        saved = nil
      }
    }
  }

  func testCommitImportsAndStoresCertificate() throws {
    let store = FakeStore()
    let expected = StoredClientCertificate(
      reference: ClientCertificateReference(
        id: "cert-1",
        displayName: "client",
        fingerprintSHA256: String(repeating: "a", count: 64),
        importedAt: Date()
      ),
      p12Data: Data([1]),
      password: "test"
    )
    let coordinator = ClientCertificateImportCoordinator(
      store: store,
      importer: { _, _, _ in expected }
    )

    let pending = coordinator.prepare(data: Data([1]), displayName: "client")
    let reference = try coordinator.commit(pending, password: "test")

    XCTAssertEqual(reference, expected.reference)
    XCTAssertEqual(store.saved?.reference, expected.reference)
  }

  func testCommitFailureStoresNothing() {
    let store = FakeStore()
    let coordinator = ClientCertificateImportCoordinator(
      store: store,
      importer: { _, _, _ in throw ClientCertificateImportError.wrongPassword }
    )

    let pending = coordinator.prepare(data: Data([1]), displayName: "client")

    XCTAssertThrowsError(try coordinator.commit(pending, password: "wrong"))
    XCTAssertNil(store.saved)
  }

  func testRemoveDeletesStoredCertificate() throws {
    let store = FakeStore()
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )
    try store.save(
      StoredClientCertificate(
        reference: reference,
        p12Data: Data([1]),
        password: "test"
      )
    )
    let coordinator = ClientCertificateImportCoordinator(store: store)

    coordinator.remove(reference)

    XCTAssertNil(store.saved)
  }
}
```

- [ ] **Step 6: Run the coordinator tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateImportCoordinator` does not exist.

- [ ] **Step 7: Implement the coordinator**

Create `API/Sources/API/Services/ClientCertificateImportCoordinator.swift`:

```swift
import Foundation

public struct PendingClientCertificateImport: Sendable {
  public let data: Data
  public let displayName: String

  public init(data: Data, displayName: String) {
    self.data = data
    self.displayName = displayName
  }
}

public final class ClientCertificateImportCoordinator {
  public typealias Importer =
    @Sendable (Data, String, String) throws -> StoredClientCertificate

  private let store: any ClientCertificateStoring
  private let importer: Importer

  public init(
    store: any ClientCertificateStoring = ClientCertificateStore.shared,
    importer: @escaping Importer = ClientCertificateImporter.importPKCS12
  ) {
    self.store = store
    self.importer = importer
  }

  public func prepare(data: Data, displayName: String) -> PendingClientCertificateImport {
    PendingClientCertificateImport(data: data, displayName: displayName)
  }

  public func commit(
    _ pending: PendingClientCertificateImport,
    password: String
  ) throws -> ClientCertificateReference {
    let certificate = try importer(
      pending.data,
      password,
      pending.displayName
    )
    try store.save(certificate)
    return certificate.reference
  }

  public func remove(_ reference: ClientCertificateReference?) {
    guard let reference else { return }
    store.delete(id: reference.id)
  }
}
```

- [ ] **Step 8: Run all API tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for store and coordinator tests.

- [ ] **Step 9: Commit**

```bash
git add API/Sources/API/Services/ClientCertificateStore.swift \
  API/Sources/API/Services/ClientCertificateImportCoordinator.swift \
  API/Tests/APITests/ClientCertificateStoreTests.swift \
  API/Tests/APITests/ClientCertificateImportCoordinatorTests.swift
git commit -m "Add client certificate keychain store and import coordinator"
```

---

### Task 4: Challenge handler, session provider, and NetworkService

**Files:**
- Create: `API/Sources/API/Network/ClientCertificateChallengeHandler.swift`
- Create: `API/Sources/API/Network/ClientCertificateCredentialProvider.swift`
- Create: `API/Sources/API/Network/ClientCertificateSessionProvider.swift`
- Modify: `API/Sources/API/NetworkService.swift`
- Test: `API/Tests/APITests/ClientCertificateCredentialTests.swift`
- Test: `API/Tests/APITests/ClientCertificateSessionProviderTests.swift`
- Test: `API/Tests/APITests/NetworkErrorCertificateTests.swift`

**Interfaces:**
- Consumes: `ClientCertificateStore`, `ClientCertificateEndpoint`, `ClientCertificateReference`.
- Produces: `ClientCertificateCredentialProvider.credential(for:store:)`, `ClientCertificateChallengeDelegate.make(for:allowedHosts:)`, `ClientCertificateSessionProvider.session(for:allowedHosts:discretionary:)`, `NetworkError.clientCertificateRequired`, `NetworkError.clientCertificateRejected`, `NetworkError.map(_:)`.

- [ ] **Step 1: Write the failing credential tests**

Create `API/Tests/APITests/ClientCertificateCredentialTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateCredentialTests: XCTestCase {
  private func fixture() throws -> Data {
    let url = try XCTUnwrap(
      Bundle.module.url(
        forResource: "client",
        withExtension: "p12",
        subdirectory: "Fixtures"
      )
    )
    return try Data(contentsOf: url)
  }

  func testCredentialIsCreatedForStoredCertificate() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)
    let stored = try ClientCertificateImporter.importPKCS12(
      data: fixture(),
      password: "test",
      displayName: "client"
    )
    try store.save(stored)

    let credential = ClientCertificateCredentialProvider.credential(
      for: stored.reference,
      store: store
    )

    XCTAssertNotNil(credential)
    XCTAssertEqual(credential?.persistence, .forSession)
  }

  func testCredentialIsNilForMissingCertificate() {
    let store = ClientCertificateStore(
      keychain: InMemoryClientCertificateKeychain()
    )
    let reference = ClientCertificateReference(
      id: "missing",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )

    XCTAssertNil(
      ClientCertificateCredentialProvider.credential(
        for: reference,
        store: store
      )
    )
  }

  func testChallengeHandlerRejectsUnrelatedHost() {
    XCTAssertFalse(
      ClientCertificateChallengeHandler.isAllowed(
        host: "other.com",
        port: 443,
        allowedHosts: ["example.com:443"]
      )
    )
    XCTAssertTrue(
      ClientCertificateChallengeHandler.isAllowed(
        host: "example.com",
        port: 443,
        allowedHosts: ["example.com:443"]
      )
    )
  }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateChallengeHandler` does not exist.

- [ ] **Step 3: Implement the credential provider and challenge handler**

Create `API/Sources/API/Network/ClientCertificateCredentialProvider.swift`:

```swift
import Foundation
import Security

public enum ClientCertificateCredentialProvider {
  public static func credential(
    for reference: ClientCertificateReference,
    store: any ClientCertificateStoring = ClientCertificateStore.shared
  ) -> URLCredential? {
    guard let stored = store.load(id: reference.id) else { return nil }

    let options = [kSecImportExportPassphrase as String: stored.password]
    var items: CFArray?
    guard
      SecPKCS12Import(
        stored.p12Data as CFData,
        options as CFDictionary,
        &items
      ) == errSecSuccess,
      let entries = items as? [[String: Any]],
      let entry = entries.first,
      let identity = entry[kSecImportItemIdentity as String] as? SecIdentity
    else {
      return nil
    }

    var certificate: SecCertificate?
    guard
      SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      let certificate
    else {
      return nil
    }

    let chain =
      entry[kSecImportItemCertChain as String] as? [SecCertificate]
      ?? [certificate]

    return URLCredential(
      identity: identity,
      certificates: chain,
      persistence: .forSession
    )
  }
}
```

Create `API/Sources/API/Network/ClientCertificateChallengeHandler.swift` with the handler and this public factory:

```swift
import Foundation

final class ClientCertificateChallengeHandler: NSObject, URLSessionTaskDelegate {
  private let certificateID: String
  private let allowedHosts: Set<String>
  private let store: any ClientCertificateStoring

  init(
    certificateID: String,
    allowedHosts: Set<String>,
    store: any ClientCertificateStoring = ClientCertificateStore.shared
  ) {
    self.certificateID = certificateID
    self.allowedHosts = allowedHosts
    self.store = store
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (
      URLSession.AuthChallengeDisposition,
      URLCredential?
    ) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod
      == NSURLAuthenticationMethodClientCertificate
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    let port = challenge.protectionSpace.port > 0
      ? challenge.protectionSpace.port
      : 443

    guard
      Self.isAllowed(
        host: challenge.protectionSpace.host,
        port: port,
        allowedHosts: allowedHosts
      ),
      let stored = store.load(id: certificateID),
      let credential = ClientCertificateCredentialProvider.credential(
        for: stored.reference,
        store: store
      )
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    completionHandler(.useCredential, credential)
  }

  static func isAllowed(
    host: String,
    port: Int,
    allowedHosts: Set<String>
  ) -> Bool {
    guard
      let endpoint = ClientCertificateEndpoint(host: host, port: port)
    else {
      return false
    }
    return allowedHosts.contains(endpoint.key)
  }
}
```

The `stored` lookup is intentional: it makes a missing certificate cancel the challenge before the provider tries to import.

Add this public factory in the same file:

```swift
public enum ClientCertificateChallengeDelegate {
  public static func make(
    for reference: ClientCertificateReference,
    allowedHosts: Set<String>
  ) -> URLSessionDelegate {
    ClientCertificateChallengeHandler(
      certificateID: reference.id,
      allowedHosts: allowedHosts
    )
  }
}
```

- [ ] **Step 4: Run the credential tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for `ClientCertificateCredentialTests`.

- [ ] **Step 5: Write the failing session provider tests**

Create `API/Tests/APITests/ClientCertificateSessionProviderTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateSessionProviderTests: XCTestCase {
  func testNilReferenceReturnsSharedBaseSession() {
    let provider = ClientCertificateSessionProvider()

    let first = provider.session(
      for: nil,
      allowedHosts: [],
      discretionary: false
    )
    let second = provider.session(
      for: nil,
      allowedHosts: [],
      discretionary: false
    )

    XCTAssertTrue(first as AnyObject === second as AnyObject)
  }

  func testCertificateSessionIsCachedAndInvalidated() {
    let provider = ClientCertificateSessionProvider()
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )

    let first = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )
    let second = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )

    XCTAssertTrue(first as AnyObject === second as AnyObject)

    provider.invalidate(certificateID: reference.id)

    let third = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )

    XCTAssertFalse(first as AnyObject === third as AnyObject)
  }
}
```

- [ ] **Step 6: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateSessionProvider` does not exist.

- [ ] **Step 7: Implement the session provider**

Create `API/Sources/API/Network/ClientCertificateSessionProvider.swift` with:

- Move the existing `NetworkService.session`, `NetworkService.discretionarySession`, and `NetworkService.userAgent` code into the provider without changing their values.
- Base sessions use the moved code.
- `#if os(watchOS)` returns `URLSession`; otherwise returns `URLSessionProxy`.
- Cache key: `certificateID|sortedAllowedHosts|discretionary`.
- `invalidate(certificateID:)` removes keys with the matching prefix.
- Certificate sessions pass `ClientCertificateChallengeHandler` as the delegate.

Use these signatures:

```swift
public final class ClientCertificateSessionProvider: @unchecked Sendable {
  public static let shared = ClientCertificateSessionProvider()

  public init() {}

  public func session(
    for reference: ClientCertificateReference?,
    allowedHosts: Set<String>,
    discretionary: Bool
  ) -> any URLSessionProtocol

  public func invalidate(certificateID: String)
}
```

- [ ] **Step 8: Modify NetworkService**

- Add `case clientCertificateRequired` and `case clientCertificateRejected` to `NetworkError`.
- Use these messages:
  - `clientCertificateRequired`: "This server requires a client certificate. Open Server > Client Certificate and import a valid certificate."
  - `clientCertificateRejected`: "The server rejected the client certificate. Open Server > Client Certificate and check the certificate."
- Add `static func map(_ error: Error) -> Error` that maps `URLError.clientCertificateRequired` and `.clientCertificateRejected` to those cases.
- Add `clientCertificate: ClientCertificateReference? = nil` to `NetworkService.init` before `headersProvider` so existing trailing closures still compile.
- In `performRequest`, use:

```swift
let server = self.server
let allowedHosts = await server?.certificateAllowedHosts ?? []
let certificate = await server?.clientCertificate ?? clientCertificate
let selectedSession = ClientCertificateSessionProvider.shared.session(
  for: certificate,
  allowedHosts: allowedHosts,
  discretionary: request.discretionary
)
```

- Remove the private static `session`, `discretionarySession`, and `userAgent` from `NetworkService`.
- Keep the raw `URLError` in `performRequest` so the existing alternative-URL fallback can still run.
- In `send`, wrap both final throws with `NetworkError.map(error)` after fallback fails or is not applicable.

- [ ] **Step 9: Write the failing error-mapping tests**

Create `API/Tests/APITests/NetworkErrorCertificateTests.swift`:

```swift
import XCTest
@testable import API

final class NetworkErrorCertificateTests: XCTestCase {
  func testClientCertificateRequiredIsMapped() {
    let mapped = NetworkError.map(URLError(.clientCertificateRequired))

    guard case NetworkError.clientCertificateRequired = mapped else {
      return XCTFail("Expected clientCertificateRequired")
    }
  }

  func testClientCertificateRejectedIsMapped() {
    let mapped = NetworkError.map(URLError(.clientCertificateRejected))

    guard case NetworkError.clientCertificateRejected = mapped else {
      return XCTFail("Expected clientCertificateRejected")
    }
  }
}
```

- [ ] **Step 10: Run all API tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for credential, provider, and error-mapping tests.

- [ ] **Step 11: Commit**

```bash
git add API/Sources/API/Network/ClientCertificateChallengeHandler.swift \
  API/Sources/API/Network/ClientCertificateSessionProvider.swift \
  API/Sources/API/NetworkService.swift \
  API/Tests/APITests/ClientCertificateCredentialTests.swift \
  API/Tests/APITests/ClientCertificateSessionProviderTests.swift \
  API/Tests/APITests/NetworkErrorCertificateTests.swift
git commit -m "Add client certificate challenge handling and sessions"
```

---

### Task 5: Registry, authentication lifecycle, and image pipeline

**Files:**
- Create: `API/Sources/API/Network/ClientCertificateRegistry.swift`
- Modify: `API/Sources/API/Services/AuthenticationService.swift`
- Modify: `API/Sources/API/Audiobookshelf.swift`
- Modify: `API/Sources/API/Extensions/ImagePipeline+AudioBooth.swift`
- Test: `API/Tests/APITests/ClientCertificateRegistryTests.swift`

**Interfaces:**
- Consumes: `ClientCertificateReference`, `Server.certificateAllowedHosts`, `ClientCertificateStore`, `ClientCertificateSessionProvider`.
- Produces: `ClientCertificateRegistry.shared.update(endpoints:reference:)`, `ClientCertificateRegistry.shared.reference(forEndpoint:)`, `AuthenticationService.updateClientCertificate(_:reference:)`, certificate-aware login methods.

- [ ] **Step 1: Write the failing registry tests**

Create `API/Tests/APITests/ClientCertificateRegistryTests.swift`:

```swift
import XCTest
@testable import API

final class ClientCertificateRegistryTests: XCTestCase {
  private let reference = ClientCertificateReference(
    id: "cert-1",
    displayName: "client",
    fingerprintSHA256: String(repeating: "a", count: 64),
    importedAt: Date()
  )

  func testRegistryReturnsReferenceForConfiguredEndpoint() {
    let registry = ClientCertificateRegistry()

    registry.update(
      endpoints: ["example.com:443"],
      reference: reference
    )

    XCTAssertEqual(
      registry.reference(forEndpoint: "example.com:443"),
      reference
    )
    XCTAssertNil(registry.reference(forEndpoint: "other.com:443"))
  }

  func testRegistryClearsWhenReferenceIsNil() {
    let registry = ClientCertificateRegistry()
    registry.update(
      endpoints: ["example.com:443"],
      reference: reference
    )

    registry.update(endpoints: ["example.com:443"], reference: nil)

    XCTAssertNil(registry.reference(forEndpoint: "example.com:443"))
  }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `swift test --package-path API`

Expected: FAIL because `ClientCertificateRegistry` does not exist.

- [ ] **Step 3: Implement the registry**

Create `API/Sources/API/Network/ClientCertificateRegistry.swift`:

```swift
import Foundation

public final class ClientCertificateRegistry: @unchecked Sendable {
  public static let shared = ClientCertificateRegistry()

  private let lock = NSLock()
  private var entries: [String: ClientCertificateReference] = [:]

  public init() {}

  public func update(
    endpoints: Set<String>,
    reference: ClientCertificateReference?
  ) {
    lock.lock()
    defer { lock.unlock() }

    entries.removeAll()

    if let reference {
      for endpoint in endpoints {
        entries[endpoint] = reference
      }
    }
  }

  public func reference(forEndpoint endpoint: String) -> ClientCertificateReference? {
    lock.lock()
    defer { lock.unlock() }
    return entries[endpoint]
  }
}
```

- [ ] **Step 4: Run the registry tests and verify they pass**

Run: `swift test --package-path API`

Expected: PASS for `ClientCertificateRegistryTests`.

- [ ] **Step 5: Update AuthenticationService**

- Add `clientCertificate: ClientCertificateReference? = nil` before `existingServerID` in these signatures:

```swift
public func login(
  serverURL: String,
  username: String,
  password: String,
  customHeaders: [String: String] = [:],
  clientCertificate: ClientCertificateReference? = nil,
  existingServerID: String? = nil
) async throws -> String

public func loginWithOIDC(
  serverURL: String,
  code: String,
  verifier: String,
  state: String?,
  cookies: [HTTPCookie],
  customHeaders: [String: String] = [:],
  clientCertificate: ClientCertificateReference? = nil,
  existingServerID: String? = nil
) async throws -> String

public func loginWithAPIKey(
  serverURL: String,
  apiKey: String,
  customHeaders: [String: String] = [:],
  clientCertificate: ClientCertificateReference? = nil,
  existingServerID: String? = nil
) async throws -> String
```

- Pass the certificate to `NetworkService(baseURL:clientCertificate:)` for the login request.
- Add `clientCertificate` to `upsertConnection` and its `Connection` construction.
- For an existing connection, use `clientCertificate ?? existingServer.clientCertificate`.
- Add:

```swift
public func updateClientCertificate(
  _ serverID: String,
  reference: ClientCertificateReference?
) {
  guard let server = servers[serverID] else { return }

  let previousID = server.clientCertificate?.id
  server.clientCertificate = reference
  connections[serverID] = Connection(server)

  if let previousID, previousID != reference?.id {
    ClientCertificateStore.shared.delete(id: previousID)
    ClientCertificateSessionProvider.shared.invalidate(certificateID: previousID)
  }

  if server.id == self.server?.id {
    ClientCertificateRegistry.shared.update(
      endpoints: server.certificateAllowedHosts,
      reference: reference
    )
  }

  ImagePipeline.shared = .audioBooth(
    customHeaders: server.customHeaders,
    clientCertificate: reference,
    allowedHosts: server.certificateAllowedHosts
  )
}
```

- In `removeServer`, delete the certificate, invalidate its session, and clear the registry when the removed server is active.
- In `switchToServer`, update the registry and image pipeline.
- In `server` didSet, update the registry and image pipeline for the new server, or clear both when the server is `nil`.
- In `updateAlternativeURL` and `setUsingAlternativeURL`, update the registry and image pipeline.
- In `updateCustomHeaders`, pass the certificate to the image pipeline.
- In `refreshToken`, create the network service with `NetworkService(baseURL: server.activeURL, server: server)` so token refresh uses the certificate.
- In `init`, update the registry for the active server after restoring connections.

- [ ] **Step 6: Update ImagePipeline**

Change `API/Sources/API/Extensions/ImagePipeline+AudioBooth.swift` to:

```swift
nonisolated static func audioBooth(
  customHeaders: [String: String]?,
  clientCertificate: ClientCertificateReference? = nil,
  allowedHosts: Set<String> = []
) -> ImagePipeline {
  ImagePipeline {
    let configuration = DataLoader.defaultConfiguration
    configuration.urlCache = nil
    configuration.httpAdditionalHeaders = customHeaders
    let loader = DataLoader(configuration: configuration)
    if let clientCertificate {
      loader.delegate = ClientCertificateChallengeHandler(
        certificateID: clientCertificate.id,
        allowedHosts: allowedHosts
      )
    }
    $0.dataLoader = loader
    $0.dataCache = dataCache
  }
}
```

- [ ] **Step 7: Update Audiobookshelf image setup**

Pass `authentication.server?.clientCertificate` and `authentication.server?.certificateAllowedHosts` in `Audiobookshelf.init`.

- [ ] **Step 8: Build and run tests**

Run: `swift test --package-path API`

Expected: PASS for all API tests.

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme AudioBooth -destination 'platform=iOS Simulator,name=iPhone 17'`

Expected: BUILD SUCCEEDED.

- [ ] **Step 9: Commit**

```bash
git add API/Sources/API/Network/ClientCertificateRegistry.swift \
  API/Sources/API/Services/AuthenticationService.swift \
  API/Sources/API/Audiobookshelf.swift \
  API/Sources/API/Extensions/ImagePipeline+AudioBooth.swift \
  API/Tests/APITests/ClientCertificateRegistryTests.swift
git commit -m "Wire client certificates into authentication and image loading"
```

---

### Task 6: Certificate settings UI and login wiring

**Files:**
- Create: `AudioBooth/AudioBooth/Screens/Servers/Server/ClientCertificate/ClientCertificateViewModel.swift`
- Create: `AudioBooth/AudioBooth/Screens/Servers/Server/ClientCertificate/ClientCertificateView.swift`
- Modify: `AudioBooth/AudioBooth/Screens/Servers/Server/ServerView.swift`
- Modify: `AudioBooth/AudioBooth/Screens/Servers/Server/ServerViewModel.swift`
- Modify: `AudioBooth/AudioBooth/Screens/Servers/Authentication/AuthenticationViewModel.swift`
- Modify: `API/Sources/API/Services/NetworkDiscoveryService.swift`

**Interfaces:**
- Consumes: `ClientCertificateImportCoordinator`, `ClientCertificateReference`, `AuthenticationService.updateClientCertificate`.
- Produces: `ClientCertificateView.Model`, `ClientCertificateViewModel`, certificate-aware server login calls.

- [ ] **Step 1: Add the certificate row to ServerView**

Add `var clientCertificate: ClientCertificateView.Model` to `ServerView.Model`. Add `clientCertificate: ClientCertificateView.Model = .init()` as the last initializer parameter, and assign it in the initializer.

In `ServerView`:

- When `model.authenticationModel != nil`, add `clientCertificateSection` after `customHeadersSection` in "Server Configuration".
- When `model.authenticationModel == nil`, add the same section to "Advanced".

Use this row:

```swift
NavigationLink(
  destination: { ClientCertificateView(model: model.clientCertificate) },
  label: {
    HStack {
      Image(systemName: "checkmark.seal")
      Text("Client Certificate")
      Spacer()
      if let name = model.clientCertificate.reference?.displayName {
        Text(name).foregroundColor(.secondary)
      }
    }
  }
)
```

- [ ] **Step 2: Implement the view model**

Create `ClientCertificateView.swift` with this model:

```swift
extension ClientCertificateView {
  @Observable
  class Model: ObservableObject {
    var reference: ClientCertificateReference?
    var isImporting = false
    var isAwaitingPassword = false
    var errorMessage: String?
    var onCertificateChanged: ((ClientCertificateReference?) -> Void)?

    init(reference: ClientCertificateReference? = nil) {
      self.reference = reference
    }

    func importFile(at url: URL) {}
    func submitPassword(_ password: String) {}
    func removeCertificate() {}
  }
}
```

Create `ClientCertificateViewModel.swift` with a subclass of `ClientCertificateView.Model`:

```swift
final class ClientCertificateViewModel: ClientCertificateView.Model {
  private let coordinator: ClientCertificateImportCoordinator
  private var pendingImport: PendingClientCertificateImport?

  init(
    reference: ClientCertificateReference?,
    coordinator: ClientCertificateImportCoordinator = ClientCertificateImportCoordinator()
  ) {
    self.coordinator = coordinator
    super.init(reference: reference)
  }

  override func importFile(at url: URL) {
    let didAccess = url.startAccessingSecurityScopedResource()
    defer {
      if didAccess {
        url.stopAccessingSecurityScopedResource()
      }
    }

    do {
      let data = try Data(contentsOf: url)
      let displayName = url.deletingPathExtension().lastPathComponent
      pendingImport = coordinator.prepare(data: data, displayName: displayName)
      isAwaitingPassword = true
      errorMessage = nil
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  override func submitPassword(_ password: String) {
    guard let pendingImport else { return }

    isImporting = true
    defer { isImporting = false }

    do {
      let reference = try coordinator.commit(pendingImport, password: password)
      self.pendingImport = nil
      self.reference = reference
      isAwaitingPassword = false
      errorMessage = nil
      onCertificateChanged?(reference)
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  override func removeCertificate() {
    coordinator.remove(reference)
    reference = nil
    errorMessage = nil
    onCertificateChanged?(nil)
  }
}
```

Use the existing `Toast` for errors in the view.

- [ ] **Step 3: Implement the view**

Create `ClientCertificateView.swift` with:

- A `Form`.
- Status row showing "Not configured" or the display name.
- Fingerprint row with uppercase colon-separated groups.
- Import date row.
- "Import Certificate" / "Replace Certificate" button.
- "Remove Certificate" destructive button with confirmation.
- A note: "OIDC sign-in uses the system browser. A system certificate profile is also required."
- `.fileImporter` with `UTType(filenameExtension: "p12")`, `UTType(filenameExtension: "pfx")`, and `.data`.
- A password sheet with `SecureField` and Cancel/Import buttons.

- [ ] **Step 4: Wire ServerViewModel**

- Add `private var pendingClientCertificate: ClientCertificateReference?`.
- Create `ClientCertificateViewModel(reference: server?.clientCertificate)`.
- Set `onCertificateChanged` with `[weak self]`:
  - Existing server: call `audiobookshelf.authentication.updateClientCertificate(server.id, reference: reference)`.
  - New server: delete the previous pending certificate if its ID differs, then set `pendingClientCertificate = reference`.
- Pass `clientCertificate: pendingClientCertificate ?? server?.clientCertificate` to `login`, `loginWithAPIKey`, and the OIDC manager.
- For the new-server OIDC manager, pass `allowedHosts` from `ClientCertificateEndpoint(url: URL(string: normalizedURL)!)`.
- Update `AuthenticationViewModel`'s username/password and API-key login calls with `clientCertificate: server.clientCertificate`.
- Update `AuthenticationViewModel`'s OIDC manager call with `clientCertificate: server.clientCertificate` and `allowedHosts: server.certificateAllowedHosts`.
- Pass the same certificate to `networkDiscovery.fetchServerStatus`.
- After successful login, set `pendingClientCertificate = nil`.
- On logout, delete any pending certificate, set `pendingClientCertificate = nil`, and reset the certificate model to `nil`.

- [ ] **Step 5: Update NetworkDiscoveryService**

Add `clientCertificate: ClientCertificateReference? = nil` to `fetchServerStatus` and pass it to `NetworkService(baseURL:clientCertificate:)`.

- [ ] **Step 6: Build the app**

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme AudioBooth -destination 'platform=iOS Simulator,name=iPhone 17'`

Expected: BUILD SUCCEEDED.

- [ ] **Step 7: Manual verification**

- Start a server behind an mTLS proxy.
- In new-server setup, import the `.p12` before login.
- Confirm `/status` and login succeed.
- Confirm a wrong password shows a toast and stores nothing.
- Open an existing server, replace the certificate, and confirm the new fingerprint appears.
- Remove the certificate and confirm the next request shows the certificate-required error.

- [ ] **Step 8: Commit**

```bash
git add AudioBooth/AudioBooth/Screens/Servers/Server/ClientCertificate \
  AudioBooth/AudioBooth/Screens/Servers/Server/ServerView.swift \
  AudioBooth/AudioBooth/Screens/Servers/Server/ServerViewModel.swift \
  AudioBooth/AudioBooth/Screens/Servers/Authentication/AuthenticationViewModel.swift \
  API/Sources/API/Services/NetworkDiscoveryService.swift
git commit -m "Add client certificate settings UI"
```

---

### Task 7: Direct file downloads, OIDC bootstrap, and image call sites

**Files:**
- Create: `AudioBooth/AudioBooth/Services/ServerSession.swift`
- Modify: `AudioBooth/AudioBooth/Services/Ebook/NarrationProbe.swift`
- Modify: `AudioBooth/AudioBooth/Screens/BookDetails/BookShareItem.swift`
- Modify: `AudioBooth/AudioBooth/Screens/EbookReader/EbookReaderViewModel.swift`
- Modify: `AudioBooth/AudioBooth/Screens/Servers/Server/OIDCAuthenticationManager.swift`
- Modify: `AudioBooth/AudioBooth/Services/DownloadManager.swift`
- Modify: `AudioBooth/AudioBooth Watch App/Services/DownloadManager.swift`
- Modify: `AudioBooth/AudioBooth Watch App/AudioBoothWatch.swift`
- Modify: `AudioBooth/AudioBooth Watch App/WatchConnectivityManager.swift`

**Interfaces:**
- Consumes: `ClientCertificateSessionProvider`, `ClientCertificateRegistry`, `Server.certificateAllowedHosts`.
- Produces: `ServerSession.current(discretionary:)`, certificate-aware direct downloads, OIDC bootstrap, and image pipelines.

- [ ] **Step 1: Add ServerSession**

Create `AudioBooth/AudioBooth/Services/ServerSession.swift`:

```swift
import API
import Foundation
import Pulse

@MainActor
enum ServerSession {
  static func current(discretionary: Bool = false) -> any URLSessionProtocol {
    let server = Audiobookshelf.shared.authentication.server
    return ClientCertificateSessionProvider.shared.session(
      for: server?.clientCertificate,
      allowedHosts: server?.certificateAllowedHosts ?? [],
      discretionary: discretionary
    )
  }
}
```

- [ ] **Step 2: Replace direct URLSession.shared calls**

Replace the three direct calls with the certificate-aware session:

- `NarrationProbe`: `let session = await ServerSession.current()` then `session.bytes(for: request, delegate: nil)`.
- `BookShareItem`: `let session = await ServerSession.current()` then `session.download(from: remoteURL, delegate: nil)`.
- `EbookReaderViewModel`: `let session = await ServerSession.current()` then `session.download(from: url, delegate: nil)`.

`ServerSession.current()` is `@MainActor`; call it from the existing async methods.

- [ ] **Step 3: Add client certificate handling to OIDC bootstrap**

- Add `clientCertificate: ClientCertificateReference?` and `allowedHosts: Set<String>` to `OIDCAuthenticationManager.init`.
- Replace `NoRedirectDelegate` with this delegate:

```swift
final class OIDCSessionDelegate: NSObject, URLSessionTaskDelegate {
  private let clientCertificate: ClientCertificateReference?
  private let allowedHosts: Set<String>

  init(
    clientCertificate: ClientCertificateReference?,
    allowedHosts: Set<String>
  ) {
    self.clientCertificate = clientCertificate
    self.allowedHosts = allowedHosts
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (
      URLSession.AuthChallengeDisposition,
      URLCredential?
    ) -> Void
  ) {
    let port = challenge.protectionSpace.port > 0
      ? challenge.protectionSpace.port
      : 443

    guard
      challenge.protectionSpace.authenticationMethod
        == NSURLAuthenticationMethodClientCertificate,
      let clientCertificate,
      let endpoint = ClientCertificateEndpoint(
        host: challenge.protectionSpace.host,
        port: port
      ),
      allowedHosts.contains(endpoint.key),
      let credential = ClientCertificateCredentialProvider.credential(
        for: clientCertificate
      )
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    completionHandler(.useCredential, credential)
  }
}
```

- Create the initial OAuth session with `URLSession(configuration: config, delegate: OIDCSessionDelegate(...), delegateQueue: nil)`.
- Pass the certificate to `loginWithOIDC`.

- [ ] **Step 4: Add certificate challenges to iOS downloads**

In `DownloadSessionDelegate`, add:

```swift
nonisolated func urlSession(
  _ session: URLSession,
  task: URLSessionTask,
  didReceive challenge: URLAuthenticationChallenge,
  completionHandler: @escaping @Sendable (
    URLSession.AuthChallengeDisposition,
    URLCredential?
  ) -> Void
) {
  let port = challenge.protectionSpace.port > 0
    ? challenge.protectionSpace.port
    : 443

  guard
    challenge.protectionSpace.authenticationMethod
      == NSURLAuthenticationMethodClientCertificate,
    let endpoint = ClientCertificateEndpoint(
      host: challenge.protectionSpace.host,
      port: port
    ),
    let reference = ClientCertificateRegistry.shared.reference(
      forEndpoint: endpoint.key
    ),
    let credential = ClientCertificateCredentialProvider.credential(
      for: reference
    )
  else {
    completionHandler(.performDefaultHandling, nil)
    return
  }

  completionHandler(.useCredential, credential)
}
```

- [ ] **Step 5: Add certificate challenges to watch downloads**

Add the same method to the watch `DownloadManager` delegate.

- [ ] **Step 6: Update watch image pipelines**

Change `ImagePipeline.watch` to accept `clientCertificate` and `allowedHosts`. Set `loader.delegate = ClientCertificateChallengeDelegate.make(for: reference, allowedHosts: allowedHosts)` when a certificate is present. Update the three call sites in `AudioBoothWatch.swift` and `WatchConnectivityManager.swift`.

- [ ] **Step 7: Build**

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme AudioBooth -destination 'platform=iOS Simulator,name=iPhone 17'`

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme "AudioBooth Watch App" -destination 'platform=watchOS Simulator,name=Apple Watch Series 10 (46mm)'`

Expected: BUILD SUCCEEDED for both.

- [ ] **Step 8: Manual verification**

- Confirm narration probing and ebook sharing work on an mTLS server.
- Confirm the OIDC bootstrap request succeeds when the certificate is configured.
- Confirm OIDC sign-in still needs a system profile.
- Confirm a book download works on iPhone.

- [ ] **Step 9: Commit**

```bash
git add AudioBooth/AudioBooth/Services/ServerSession.swift \
  AudioBooth/AudioBooth/Services/Ebook/NarrationProbe.swift \
  AudioBooth/AudioBooth/Screens/BookDetails/BookShareItem.swift \
  AudioBooth/AudioBooth/Screens/EbookReader/EbookReaderViewModel.swift \
  AudioBooth/AudioBooth/Screens/Servers/Server/OIDCAuthenticationManager.swift \
  AudioBooth/AudioBooth/Services/DownloadManager.swift \
  "AudioBooth/AudioBooth Watch App/Services/DownloadManager.swift" \
  "AudioBooth/AudioBooth Watch App/AudioBoothWatch.swift" \
  "AudioBooth/AudioBooth Watch App/WatchConnectivityManager.swift"
git commit -m "Apply client certificates to downloads and OIDC bootstrap"
```

---

### Task 8: Apple Watch certificate sync

**Files:**
- Modify: `AudioBooth/AudioBooth/Services/WatchConnectivityManager.swift`
- Modify: `AudioBooth/AudioBooth Watch App/WatchConnectivityManager.swift`

**Interfaces:**
- Consumes: `ClientCertificateStore`, `StoredClientCertificate`, `Connection.clientCertificate`.
- Produces: watch certificate file transfer and resend requests.

- [ ] **Step 1: Send the certificate from iPhone to watch**

In the phone `WatchConnectivityManager`:

- Pass `clientCertificate: server.clientCertificate` when building the `Connection` in `watchConnection()`.
- Track `lastSentCertificateID`.
- Add `sendClientCertificateToWatchIfNeeded()`.
- When the active server certificate ID differs from `lastSentCertificateID`, write the stored PKCS#12 data to a temporary file and call `session.transferFile(_:metadata:)`.
- Metadata keys: `command` = `clientCertificate`, `id`, `displayName`, `fingerprint`, `importedAt`, `password`.
- Call this method from `updateContext()`.
- Handle `requestClientCertificate` in `didReceiveUserInfo` and `didReceiveMessage`, and resend.

- [ ] **Step 2: Receive the certificate on watch**

In the watch `WatchConnectivityManager`:

- Implement `session(_:didReceive:)` for `WCSessionFile`.
- Decode the metadata and read the file data.
- Build `StoredClientCertificate` and save it with `ClientCertificateStore.shared`.
- Update `ClientCertificateRegistry.shared` and `ImagePipeline.shared` with the new certificate.
- Delete the previous certificate when the connection changes or becomes `nil`.

- [ ] **Step 3: Request a missing certificate**

In `handleConnection`, after restoring the connection:

- If `connection.clientCertificate` exists and `ClientCertificateStore.shared.load(id:)` is `nil`, send `requestClientCertificate` with `transferUserInfo`.
- If the connection has no certificate, delete the previous watch certificate.
- Handle `requestClientCertificate` in the phone's `didReceiveUserInfo` and resend the file.

- [ ] **Step 4: Use the certificate on watch**

- Ensure `NetworkService` on watch receives the active server's certificate.
- Ensure watch image pipelines pass the certificate.
- Ensure watch downloads use the registry.

- [ ] **Step 5: Build**

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme AudioBooth -destination 'platform=iOS Simulator,name=iPhone 17'`

Run: `xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme "AudioBooth Watch App" -destination 'platform=watchOS Simulator,name=Apple Watch Series 10 (46mm)'`

Expected: BUILD SUCCEEDED for both.

- [ ] **Step 6: Manual verification**

- Import a certificate on iPhone.
- Confirm the watch receives it.
- Confirm the watch can download a book from the mTLS server.
- Delete the watch app data and confirm it requests and receives the certificate again.
- Remove the certificate on iPhone and confirm the watch deletes its copy.

- [ ] **Step 7: Commit**

```bash
git add AudioBooth/AudioBooth/Services/WatchConnectivityManager.swift \
  "AudioBooth/AudioBooth Watch App/WatchConnectivityManager.swift"
git commit -m "Sync client certificates to Apple Watch"
```

---

### Task 9: Documentation

**Files:**
- Create: `docs/mtls.md`
- Modify: `README.md`

- [ ] **Step 1: Write the user guide**

Create `docs/mtls.md` with:

- What mTLS is and when to use it.
- How to create a `.p12` with `openssl pkcs12 -export`.
- How to import, replace, and remove it.
- Which traffic uses the certificate.
- The OIDC system-browser limitation.
- How watch sync works.
- Troubleshooting: wrong password, missing private key, certificate rejected, watch resend.

- [ ] **Step 2: Add a README feature line**

Add "mTLS client-certificate authentication" to the feature list.

- [ ] **Step 3: Verify links**

Run: `rg -n "mtls.md" README.md`

Expected: the new link is present and points to `docs/mtls.md`.

- [ ] **Step 4: Commit**

```bash
git add docs/mtls.md README.md
git commit -m "Document mTLS client certificate support"
```

---

### Task 10: Final verification and cleanup

**Files:**
- No new files.

- [ ] **Step 1: Run formatting**

Run:

```bash
swift-format format --in-place --recursive API AudioBooth
swift-format lint --strict --recursive API AudioBooth
```

Expected: lint exits 0.

- [ ] **Step 2: Run API tests**

Run: `swift test --package-path API`

Expected: all tests pass.

- [ ] **Step 3: Build app and watch app**

Run:

```bash
xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme AudioBooth -destination 'platform=iOS Simulator,name=iPhone 17'
xcodebuild build -project AudioBooth/AudioBooth.xcodeproj -scheme "AudioBooth Watch App" -destination 'platform=watchOS Simulator,name=Apple Watch Series 10 (46mm)'
```

Expected: both builds succeed.

- [ ] **Step 4: Search for secret leaks**

Run:

```bash
rg -n "p12Data|password" API/Sources AudioBooth --glob '*.swift'
```

Expected: no logging of `p12Data` or certificate passwords. Review every match.

- [ ] **Step 5: Search for remaining direct sessions**

Run:

```bash
rg -n "URLSession.shared" AudioBooth --glob '*.swift'
```

Expected: no server-facing direct `URLSession.shared` calls remain. Widgets may still use the shared pipeline.

- [ ] **Step 6: Commit any cleanup**

```bash
git add -A
git commit -m "Format and verify mTLS support"
```
